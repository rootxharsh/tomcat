# Session Replication Deserialization Gadget Chain Analysis

## Executive Summary

The Tomcat session replication subsystem (`ReplicationStream`) performs deserialization with **zero `ObjectInputFilter`**. While individual Tomcat components provide powerful RCE primitives (especially the EL subsystem), a fully self-contained auto-triggering chain from `readObject()` to arbitrary code execution using **only** modern JDK 21+ and Tomcat classes has significant gaps. However, the attack surface is critical and exploitable under realistic conditions.

---

## 1. The Unfiltered Deserialization Surface

### ReplicationStream (No Filter)

**File:** `java/org/apache/catalina/tribes/io/ReplicationStream.java`

`ReplicationStream` extends `ObjectInputStream` with:
- **No `ObjectInputFilter`** / `setObjectInputFilter()`
- **No class whitelist/blocklist**
- `resolveClass()` delegates directly to `Class.forName()` via the webapp classloader array
- All application classes + Tomcat library classes are reachable

### Session Attribute Deserialization (No Validation)

**File:** `java/org/apache/catalina/session/StandardSession.java:1183-1187`

```java
for (int i = 0; i < n; i++) {
    String name = (String) stream.readObject();
    final Object value = stream.readObject();  // ANY Serializable object
```

Every session attribute value is deserialized via raw `readObject()` with no type checking.

### DeltaRequest Attribute Deserialization

**File:** `java/org/apache/catalina/ha/session/DeltaRequest.java` (inner class `AttributeInfo`)

```java
public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    // ...
    info.value = in.readObject();  // Arbitrary object deserialization
}
```

### RpcMessage Arbitrary Deserialization

**File:** `java/org/apache/catalina/tribes/group/RpcMessage.java:52`

```java
message = (Serializable) in.readObject();  // ANY Serializable object
```

---

## 2. Available Gadget Components

### 2.1 Sink: FunctionMapperImpl (Arbitrary Static Method Invocation)

**File:** `java/org/apache/el/lang/FunctionMapperImpl.java`

The `Function` inner class (Externalizable) stores:
- `owner` — arbitrary class name (line 74)
- `name` — arbitrary method name (line 75)
- `types` — arbitrary parameter type names (line 76)

On `getMethod()` (line 124-135):
```java
public Method getMethod() {
    if (this.m == null) {
        Class<?> t = ReflectionUtil.forName(this.owner);   // Loads ANY class
        Class<?>[] p = ReflectionUtil.toTypeArray(this.types);
        this.m = t.getMethod(this.name, p);                // Resolves ANY method
    }
    return this.m;
}
```

### 2.2 Invocation: AstFunction.getValue() (Static Method Execution)

**File:** `java/org/apache/el/parser/AstFunction.java:77-194`

```java
Method m = fnMapper.resolveFunction(this.prefix, this.localName);
// ...
result = m.invoke(null, params);  // Invokes resolved static method
```

Combined with FunctionMapperImpl, this can call **any static method** with attacker-controlled arguments. For example, mapping `Runtime.getRuntime()` and chaining to `exec()`.

### 2.3 Expression Carrier: ValueExpressionImpl (Externalizable)

**File:** `java/org/apache/el/ValueExpressionImpl.java:182-190`

```java
public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    this.expr = in.readUTF();                              // EL expression string
    // ...
    this.fnMapper = (FunctionMapper) in.readObject();      // Attacker-controlled FunctionMapper
    this.varMapper = (VariableMapper) in.readObject();     // Attacker-controlled VariableMapper
}
```

When `getValue(ELContext)` is called, it evaluates the expression using the attacker's FunctionMapper, triggering arbitrary static method invocation via the chain above.

### 2.4 JDK Sink: TemplatesImpl (Bytecode Execution)

**Class:** `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` (JDK built-in, Serializable)

When `getOutputProperties()` or `newTransformer()` is called:
1. `getTransletInstance()` → `defineTransletClasses()`
2. Custom ClassLoader calls `defineClass()` with attacker's `_bytecodes` field
3. Instantiates the loaded class → attacker's constructor/static initializer runs
4. **Result: Arbitrary code execution**

---

## 3. Available Triggers (readObject → method call)

### 3.1 HashMap (JDK) → hashCode()

`HashMap.readObject()` calls `hashCode()` on all deserialized keys. This is the most reliable deserialization trigger.

### 3.2 BadAttributeValueExpException (JDK) → toString()

`javax.management.BadAttributeValueExpException.readObject()` calls `toString()` on its `val` field.

### 3.3 PriorityQueue (JDK) → compareTo() / Comparator.compare()

`PriorityQueue.readObject()` calls `compareTo()` on elements (or uses the provided `Comparator`).

### 3.4 Session Replication Callbacks (Tomcat) → valueBound() / sessionDidActivate()

Post-deserialization, Tomcat fires:
- `HttpSessionBindingListener.valueBound()` via `DeltaRequest.execute()` → `session.setAttribute()`
- `HttpSessionActivationListener.sessionDidActivate()` via `StandardManager.load()` → `session.activate()`

---

## 4. Gap Analysis: Why Auto-Trigger RCE is Hard

The **fundamental gap** is bridging from a trigger method (`hashCode`, `toString`, `compareTo`) to an EL evaluation or `TemplatesImpl.getOutputProperties()`.

| Trigger | Target Method | Bridge Available? |
|---------|--------------|-------------------|
| HashMap → hashCode() | ValueExpressionImpl.hashCode() | Calls `getNode().hashCode()` — only **parses** the expression, does NOT evaluate it |
| HashMap → hashCode() | TemplatesImpl.hashCode() | Returns a simple hash, does NOT trigger bytecode loading |
| BadAttributeValueExpException → toString() | ValueExpressionImpl.toString() | Returns `"ValueExpression[expr]"` literal — no evaluation |
| PriorityQueue → compareTo() | — | No Serializable Comparator on Tomcat classpath that calls getters/evaluates EL |
| valueBound() | — | No HttpSessionBindingListener on Tomcat classpath that triggers EL/JNDI/reflection |
| sessionDidActivate() | — | Not called by DeltaManager (only by StandardManager/PersistentManagerBase for file-based persistence) |

**The EL infrastructure deliberately separates parsing from evaluation.** Parsing (triggered by `hashCode()`) produces an AST. Evaluation (triggered by `getValue(ELContext)`) requires an `ELContext`. No `readObject()` path on the Tomcat classpath provides an `ELContext`.

---

## 5. Complete Chains That DO Work

### 5.1 URLDNS Chain (DNS Exfiltration — Always Works)

**Components:** JDK only (`HashMap` + `java.net.URL`)

```
HashMap.readObject()
  → URL.hashCode()
    → URLStreamHandler.hashCode(URL)
      → InetAddress.getByName(host)    ← DNS lookup to attacker domain
```

- **Confirms vulnerability exists** via out-of-band DNS
- No RCE, but proves the deserialization surface is reachable and unfiltered
- Works on ALL JDK versions

### 5.2 TemplatesImpl Chain (RCE — Older JDKs Only)

**Components:** JDK only (pre-8u71)

```
HashSet.readObject()
  → HashMap.put() → hash collision
    → Proxy(Templates).equals(TemplatesImpl)
      → AnnotationInvocationHandler.equalsImpl(TemplatesImpl)
        → TemplatesImpl.getOutputProperties()
          → defineClass(_bytecodes)       ← ARBITRARY CODE EXECUTION
```

- Works on JDK 7 and JDK 8 < u71
- Patched via AnnotationInvocationHandler.readObject() validation

### 5.3 Commons-Collections / BeanUtils Chains (RCE — If Library Present)

If ANY of these libraries are on the webapp's classpath (extremely common):
- `commons-collections` (3.x or 4.x)
- `commons-beanutils`
- `spring-core` + `spring-beans`
- `groovy`

Then full RCE chains are trivially available through ReplicationStream.

**Example with commons-beanutils:**
```
PriorityQueue.readObject()
  → BeanComparator.compare()
    → PropertyUtils.getProperty(TemplatesImpl, "outputProperties")
      → TemplatesImpl.getOutputProperties()
        → defineClass(_bytecodes)       ← ARBITRARY CODE EXECUTION
```

### 5.4 DBCP JNDI Chain (SSRF/RCE — Requires Application Interaction)

**Components:** Tomcat DBCP2 (`InstanceKeyDataSource` subclasses)

`PerUserPoolDataSource` / `SharedPoolDataSource` are Serializable. Their `testCPDS()` method performs:

```java
ctx = new InitialContext(jndiEnvironment);  // Attacker-controlled environment
Object ds = ctx.lookup(dataSourceName);     // Attacker-controlled JNDI name
```

Both `jndiEnvironment` and `dataSourceName` are deserialized fields. However, `testCPDS()` is NOT called from `readObject()` — it's only called on `getConnection()`. So this requires the deserialized DataSource to be used by the application.

### 5.5 EL RCE Primitive (Requires Evaluation Trigger)

**Components:** Tomcat EL (`FunctionMapperImpl` + `ValueExpressionImpl`)

```
ValueExpressionImpl.getValue(ELContext)
  → AstFunction.getValue(ctx)
    → FunctionMapperImpl.resolveFunction()
      → Function.getMethod()
        → ReflectionUtil.forName("java.lang.Runtime")
        → Runtime.class.getMethod("exec", String.class)
      → Method.invoke(null, "attacker-command")     ← ARBITRARY CODE EXECUTION
```

This is a **complete RCE primitive** once `getValue()` is called with any `ELContext`. The gap is that no auto-trigger from `readObject()` reaches `getValue()` on the Tomcat classpath.

---

## 6. Post-Deserialization Callback Paths

Even without auto-triggering from `readObject()`, the session replication system provides callback surfaces:

### 6.1 DeltaRequest.execute() → setAttribute() → valueBound()

**File:** `java/org/apache/catalina/ha/session/DeltaRequest.java:183`

```java
session.setAttribute(info.getName(), info.getValue(), notifyListeners, false);
```

If `notifyListeners` is true and the value implements `HttpSessionBindingListener`, `valueBound()` fires on the deserialized object. No existing Tomcat class exploits this, but future classes or custom application code could.

### 6.2 StandardSession.activate() → sessionDidActivate()

**File:** `java/org/apache/catalina/session/StandardSession.java:728-735`

```java
if (attribute instanceof HttpSessionActivationListener) {
    ((HttpSessionActivationListener) attribute).sessionDidActivate(event);
}
```

Called by `StandardManager.load()` and `PersistentManagerBase`, but **NOT** by `DeltaManager`. Only relevant for file-based session persistence, not cluster replication.

---

## 7. BeanFactory Analysis (forceString Removed)

**File:** `java/org/apache/naming/factory/BeanFactory.java`

The classic `BeanFactory` + `ResourceRef` JNDI gadget relied on `forceString` to call arbitrary setter methods. In this version, `forceString` has been **removed** (line 108-111 shows only a warning). BeanFactory now only calls standard JavaBean property setters, significantly limiting exploitation. The Tomcat-specific extension (lines 156-166) still tries String-parameter overloads, but this only allows calling `setXxx(String)` methods on the target bean.

---

## 8. Conclusions

### What IS Exploitable
1. **URLDNS** — Always works, proves the unfiltered deserialization surface
2. **Full RCE if gadget libraries are on the classpath** — Very common in real deployments (commons-collections, spring, etc.)
3. **Full RCE on older JDKs** — TemplatesImpl chain via AnnotationInvocationHandler
4. **EL-based RCE primitive** — Complete once an evaluation trigger exists

### What's Missing for Pure Tomcat+JDK21 RCE
- A **bridge gadget** from `readObject()` triggers (`hashCode`, `toString`, `compareTo`) to EL `getValue()` or `TemplatesImpl.getOutputProperties()`
- No Serializable `Comparator`, `InvocationHandler`, or `HttpSessionBindingListener` on the Tomcat classpath that performs method forwarding to arbitrary targets

### Root Cause
`ReplicationStream` extends `ObjectInputStream` with **no `ObjectInputFilter`**. Adding a filter that restricts deserialization to known-safe session types would eliminate the entire attack surface.

### Risk Rating: CRITICAL
Despite the auto-trigger gap with modern JDK, this is critical because:
- Real-world deployments almost always have gadget libraries
- New JDK gadget chains are discovered periodically
- The fundamental design (no filter) is a time bomb
- URLDNS proves the vulnerability is reachable from the cluster network
