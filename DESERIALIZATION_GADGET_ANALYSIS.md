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
- `HttpSessionBindingListener.valueBound()` via `DeltaRequest.execute()` → `session.setAttribute()` (when `notifyListenersOnReplication=true`, which is the **default**)
- **`HttpSessionActivationListener.sessionDidActivate()`** via `DeltaSession.doReadObject()` → `activate()` (**CORRECTED**: this IS called during cluster replication, not just file-based persistence)

**Critical correction**: `DeltaSession.doReadObject()` at line 767 calls `activate()` DIRECTLY after deserializing all session attributes and listeners. This means `sessionDidActivate()` fires on every deserialized session attribute that implements `HttpSessionActivationListener` during cluster session state transfer via `DeltaManager.deserializeSessions()` → `session.readObjectData(ois)` → `doReadObject()` → `activate()`.

---

## 4. Gap Analysis: Why Auto-Trigger RCE is Hard

The **fundamental gap** is bridging from a trigger method (`hashCode`, `toString`, `compareTo`) to an EL evaluation or `TemplatesImpl.getOutputProperties()`.

| Trigger | Target Method | Bridge Available? |
|---------|--------------|-------------------|
| HashMap → hashCode() | ValueExpressionImpl.hashCode() | Calls `getNode().hashCode()` — only **parses** the expression, does NOT evaluate it |
| HashMap → hashCode() | TemplatesImpl.hashCode() | Returns a simple hash, does NOT trigger bytecode loading |
| BadAttributeValueExpException → toString() | ValueExpressionImpl.toString() | Returns `"ValueExpression[expr]"` literal — no evaluation |
| PriorityQueue → compareTo() | — | No Serializable Comparator on Tomcat classpath that calls getters/evaluates EL |
| valueBound() | — | No HttpSessionBindingListener on Tomcat classpath that triggers EL/JNDI/reflection (but callback IS fired via DeltaRequest with default settings) |
| sessionDidActivate() | — | **CORRECTED**: IS called by DeltaSession.doReadObject() line 767 during cluster replication. No HttpSessionActivationListener on Tomcat classpath bridges to EL/RCE |

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

### 6.2 DeltaSession.doReadObject() → activate() → sessionDidActivate() (CORRECTED)

**File:** `java/org/apache/catalina/ha/session/DeltaSession.java:767`

```java
// At the end of doReadObject():
activate();  // line 767
```

**File:** `java/org/apache/catalina/session/StandardSession.java:728-735`

```java
if (attribute instanceof HttpSessionActivationListener) {
    ((HttpSessionActivationListener) attribute).sessionDidActivate(event);
}
```

**CORRECTED**: `DeltaSession.doReadObject()` calls `activate()` DIRECTLY at line 767 after deserializing all session attributes. This is called during cluster replication via:
- `DeltaManager.deserializeSessions()` → `session.readObjectData(ois)` → `doReadObject()` → `activate()`
- `DeltaSession.readExternal()` → `doReadObject()` → `activate()`

This means **any deserialized session attribute implementing `HttpSessionActivationListener` gets its `sessionDidActivate()` callback fired during cluster session state transfer**. The prior analysis incorrectly stated this was only called by `StandardManager.load()` for file-based persistence.

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

---

## 9. Existing PoC Files (Prior Work in Repository)

The repository already contains proof-of-concept files that demonstrate the FunctionMapperImpl RCE primitive:

- **`GadgetPOC.java`** — Demonstrates crafting a FunctionMapperImpl with `Function(owner=Runtime, name=exec)`, serializing it, deserializing it, then manually calling `resolveFunction()` to obtain a live `Method` handle to `Runtime.exec(String)`. Proves the method resolution works with zero validation.

- **`PayloadGenerator.java`** / **`ExploitPayloadGenerator.java`** — Generate serialized payload files containing the malicious FunctionMapperImpl.

- **`ExploitClient.java`** — End-to-end client that sends the payload to a vulnerable endpoint. Lines 133-136 claim that `sessionDidActivate()` triggers EL evaluation — this is partially correct: `DeltaSession.doReadObject()` DOES call `activate()` (see corrected Section 6.2), but no existing class bridges from `sessionDidActivate()` to EL `getValue()`.

- **`DeltaSessionActivateChainPOC.java`** — Demonstrates the corrected finding that `DeltaSession.readExternal()` → `activate()` → `sessionDidActivate()` IS called during cluster replication. Documents both callback paths (sessionDidActivate via activate(), valueBound via DeltaRequest.execute()) and the FunctionMapperImpl RCE primitive.

- **`exploit-app/`** — Contains a `DeserializeServlet` that accepts POST requests with serialized objects and calls `readObject()` with no filtering.

**Key observation:** All existing PoCs require **manual invocation** of `resolveFunction()` after deserialization (step 4 in GadgetPOC.java). None demonstrate an auto-triggering chain from `readObject()` to code execution. This confirms the bridge gap identified in Section 4.

---

## 10. Additional Attack Vectors Investigated

### 10.1 DeltaRequest SessionListener Injection

`DeltaRequest.execute()` handles `TYPE_LISTENER` with `ACTION_SET`:
```java
session.addSessionListener(listener, false);
```

`SingleSignOnListener` implements `SessionListener, Serializable` and could be injected via a crafted delta. However, its `sessionEvent()` method only performs SSO management operations (session destroy/ID change) — no EL evaluation or reflection.

### 10.2 ValueExpressionLiteral Class Loading

`ValueExpressionLiteral.readExternal()` calls `ReflectionUtil.forName(type)` during deserialization, which triggers `Class.forName()` and runs the target class's static initializer. However, no JDK/Tomcat class has a dangerous static initializer that would achieve code execution.

### 10.3 DBCP InstanceKeyDataSource Deserialization

`SharedPoolDataSource.readObject()` calls `readObjectImpl()` which goes through the factory pattern, but `getReference()` only includes `instanceKey` — not `dataSourceName` or `jndiEnvironment`. The factory creates a clean, unconfigured instance. No JNDI lookup is triggered from `readObject()`.

### 10.4 Proxy-based Approaches

A `java.lang.reflect.Proxy` implementing `HttpSessionActivationListener` or `HttpSessionBindingListener` would need a Serializable `InvocationHandler`. Two JDK-provided options exist:

1. **`sun.reflect.annotation.AnnotationInvocationHandler`** — In JDK 17+ validates the annotation type during `readObject()` and rejects non-annotation interfaces. Dead end.

2. **`java.rmi.server.RemoteObjectInvocationHandler`** — Extends `RemoteObject` (Serializable). Could potentially bridge `sessionDidActivate()` to a JRMP network call to an attacker-controlled server. However, `invokeRemoteMethod()` has TWO checks:
   - `proxy instanceof Remote` — would pass if Proxy also implements `Remote`
   - `Remote.isAssignableFrom(method.getDeclaringClass())` — FAILS because `sessionDidActivate()` is declared in `HttpSessionActivationListener`, not a `Remote` subinterface

   This second check kills the JRMP bridge approach. The method's declaring class must extend `java.rmi.Remote`, which `HttpSessionActivationListener` does not.

### 10.5 Serializable Comparator Search

Only one Serializable Comparator exists on the Tomcat classpath: `AbsoluteOrder.AbsoluteComparator` (compares cluster Member hosts/ports). It does not call getters, evaluate EL, or perform reflection — dead end for PriorityQueue-based chains.

### 10.6 CrawlerHttpSessionBindingListener

`CrawlerSessionManagerValve.CrawlerHttpSessionBindingListener` implements both `HttpSessionBindingListener` and `Serializable`. However, its `valueUnbound()` only calls `clientIdSessionId.remove()` — no dangerous operations. No `valueBound()` override.

### 10.7 MapMessage.toString() Investigation

`AbstractReplicatedMap.MapMessage.toString()` was investigated as a potential bridge via `BadAttributeValueExpException.readObject()` → `toString()`. However, `toString()` accesses the `key` and `value` FIELDS directly (`"key=" + key`), NOT the `getKey()`/`getValue()` methods that would trigger `XByteBuffer.deserialize()`. Dead end.

### 10.8 MethodExpressionImpl / ValueExpressionLiteral Class Loading

`MethodExpressionImpl.readExternal()` calls `ReflectionUtil.forName(type)` for the `expectedType` field, and `ReflectionUtil.toTypeArray()` for parameter types. Both trigger `Class.forName()` which runs static initializers. However, no JDK/Tomcat class has a static initializer that achieves code execution.

### 10.9 BCEL Classes

Tomcat's stripped BCEL at `org.apache.tomcat.util.bcel` contains NO Serializable classes — only classfile parsing utilities. Not usable in deserialization chains.

---

## 11. Corrected Callback Path Summary

### Two Confirmed Post-Deserialization Callback Paths in Cluster Replication

| Path | Entry Point | Callback | Default Active? |
|------|-------------|----------|-----------------|
| Full session state transfer | `DeltaManager.deserializeSessions()` → `session.readObjectData()` → `doReadObject()` → `activate()` | `sessionDidActivate()` on `HttpSessionActivationListener` attributes | **YES** (always) |
| Delta attribute updates | `DeltaSession.deserializeAndExecuteDeltaRequest()` → `DeltaRequest.execute()` → `session.setAttribute()` | `valueBound()` on `HttpSessionBindingListener` attributes | **YES** (`notifyListenersOnReplication` defaults to `true`) |

Both callbacks fire on attacker-controlled deserialized objects during cluster replication. The bridge gap remains: no Serializable class on the Tomcat+JDK 21 classpath implements these listener interfaces with behavior that chains to EL evaluation or arbitrary method invocation.

### What This Means for Exploitability

1. **Future classes**: Any Serializable `HttpSessionActivationListener` or `HttpSessionBindingListener` added to the Tomcat classpath could complete the chain
2. **Webapp classes**: Application-specific implementations of these interfaces could be exploited if they perform dangerous operations in their callback methods
3. **The callback IS reachable**: Prior analysis incorrectly excluded this path — it is active during standard cluster session replication
