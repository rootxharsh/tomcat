# Tomcat Deserialization Gadget Analysis

## Executive Summary

Analysis of the Apache Tomcat codebase reveals several deserialization gadget
components that can be chained to achieve **arbitrary code/command execution**
and **JNDI injection**. The most critical finding is a gadget chain involving
the EL (Expression Language) implementation classes that allows arbitrary
class loading and method resolution during deserialization, which, when
combined with a post-deserialization evaluation trigger, yields full RCE.

---

## Finding 1: EL FunctionMapper Arbitrary Method Resolution (HIGH)

**Impact**: Arbitrary class loading + arbitrary public method handle resolution
**Classes involved**:
- `org.apache.el.lang.FunctionMapperImpl` (Externalizable)
- `org.apache.el.lang.FunctionMapperImpl.Function` (Externalizable)
- `org.apache.el.util.ReflectionUtil`

### Description

`FunctionMapperImpl.Function` stores method metadata as plain strings
(`owner`, `name`, `types`) during serialization. On deserialization via
`readExternal()`, these strings are restored from the stream. When
`getMethod()` is subsequently called, it performs:

```java
// FunctionMapperImpl.java:124-135
public Method getMethod() {
    if (this.m == null) {
        try {
            Class<?> t = ReflectionUtil.forName(this.owner);       // loads ANY class
            Class<?>[] p = ReflectionUtil.toTypeArray(this.types); // loads param types
            this.m = t.getMethod(this.name, p);                    // resolves ANY public method
        } catch (Exception e) { }
    }
    return this.m;
}
```

`ReflectionUtil.forName()` calls `Class.forName(name, true, contextClassLoader)`
with **no whitelist, no validation, and initialize=true** (runs static
initializers).

### Trigger

`getMethod()` is called from `FunctionMapperImpl.resolveFunction()` which is
invoked during EL expression evaluation (e.g., via `ValueExpressionImpl.getValue()`
or `MethodExpressionImpl.invoke()`).

### Exploitation

Craft a serialized `FunctionMapperImpl` with a `Function` entry where:
- `owner = "java.lang.Runtime"`
- `name = "exec"`
- `types = ["java.lang.String"]`

When evaluation is triggered, `resolveFunction()` returns a `Method` handle to
`Runtime.exec(String)`.

---

## Finding 2: ValueExpressionImpl/MethodExpressionImpl Class Initialization (MEDIUM)

**Impact**: Arbitrary class static initialization during deserialization
**Classes**:
- `org.apache.el.ValueExpressionImpl` (Externalizable)
- `org.apache.el.MethodExpressionImpl` (Externalizable)

### Description

During `readExternal()`, both classes call `ReflectionUtil.forName(type)` with
an attacker-controlled type string read from the stream:

```java
// ValueExpressionImpl.java:182-190
public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    this.expr = in.readUTF();
    String type = in.readUTF();
    if (!type.isEmpty()) {
        this.expectedType = ReflectionUtil.forName(type); // Class.forName(type, true, cl)
    }
    this.fnMapper = (FunctionMapper) in.readObject();     // deserializes FunctionMapper
    this.varMapper = (VariableMapper) in.readObject();    // deserializes VariableMapper
}
```

`Class.forName(type, true, classLoader)` with `initialize=true` executes the
static initializer block of the specified class.

Additionally, `MethodExpressionImpl.readExternal()` calls
`ReflectionUtil.toTypeArray()` which loads multiple classes from an
attacker-controlled `String[]`.

### hashCode() Auto-Trigger

`ValueExpressionImpl.hashCode()` calls `getNode()` which calls
`ExpressionBuilder.createNode(this.expr)`. This **parses** the EL expression
string into an AST but does **not evaluate** it. Parsing alone has no
dangerous side effects (function resolution happens at build-time via
`ExpressionBuilder.build()`, not `createNode()`).

When placed as a key in a `HashMap`, deserialization auto-triggers `hashCode()`
via `HashMap.readObject()`, but this only causes expression parsing.

---

## Finding 3: InstanceKeyDataSource JNDI Injection (HIGH)

**Impact**: JNDI injection leading to RCE
**Classes**:
- `org.apache.tomcat.dbcp.dbcp2.datasources.SharedPoolDataSource` (Serializable)
- `org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource` (Serializable)

### Description

Both classes extend `InstanceKeyDataSource` which is `Serializable`. The
attacker-controlled fields `dataSourceName` (String) and `jndiEnvironment`
(Properties) survive deserialization.

When `getConnection()` is called post-deserialization, the call chain is:

```
getConnection() → testCPDS() → new InitialContext(jndiEnvironment).lookup(dataSourceName)
```

```java
// InstanceKeyDataSource.java:1256-1273
protected ConnectionPoolDataSource testCPDS(String userName, String userPassword)
        throws NamingException, SQLException {
    ConnectionPoolDataSource cpds = this.dataSource;
    if (cpds == null) {
        Context ctx = (jndiEnvironment == null)
            ? new InitialContext()
            : new InitialContext(jndiEnvironment);
        final Object ds = ctx.lookup(dataSourceName); // JNDI injection
        // ...
    }
}
```

The `dataSource` field is transient (always null after deserialization),
guaranteeing the JNDI lookup path is taken. Both `dataSourceName` and
`jndiEnvironment` are attacker-controlled.

### Trigger Limitation

Requires `getConnection()` to be called after deserialization. Not
auto-triggered during deserialization itself. Useful as a second-stage
gadget when combined with something that invokes DataSource methods.

---

## Finding 4: Session Replication - Unfiltered Deserialization (CRITICAL)

**Impact**: Arbitrary object graph deserialization + listener callbacks
**Classes**:
- `org.apache.catalina.ha.session.DeltaSession`
- `org.apache.catalina.session.StandardSession`
- `org.apache.catalina.tribes.io.ReplicationStream`

### Description

The cluster replication mechanism deserializes session data using
`ReplicationStream`, which extends `ObjectInputStream` with **no
`ObjectInputFilter`**. Session attributes are deserialized via plain
`stream.readObject()` with no class restrictions.

```java
// StandardSession.java - session attribute deserialization
for (int i = 0; i < n; i++) {
    String name = (String) stream.readObject();
    final Object value = stream.readObject(); // ANY Serializable object
    attributes.put(name, value);
}
```

After attribute deserialization, callbacks fire on deserialized objects:

1. **`HttpSessionBindingListener.valueBound()`** - called during
   `setAttribute()` when `notifyListenersOnReplication=true`
2. **`HttpSessionActivationListener.sessionDidActivate()`** - called during
   `activate()` after session deserialization
3. **`SessionListener`** objects are deserialized and their methods invoked

### Exploitation

An attacker who can send messages on the cluster channel (e.g., via network
access to the cluster multicast/TCP channel) can embed any serializable
gadget chain as a session attribute. The chain executes during
deserialization with no filtering.

---

## Finding 5: PoolProperties Arbitrary Class Instantiation (MEDIUM)

**Impact**: Arbitrary class loading and instantiation via no-arg constructor
**Class**: `org.apache.tomcat.jdbc.pool.PoolProperties` (Serializable)

### Description

`setValidatorClassName(String className)` loads and instantiates an
arbitrary class:

```java
// PoolProperties.java:551-578
public void setValidatorClassName(String className) {
    this.validatorClassName = className;
    validator = null;
    if (className == null) return;
    Class<Validator> validatorClass = (Class<Validator>) ClassLoaderUtil.loadClass(
        className, PoolProperties.class.getClassLoader(),
        Thread.currentThread().getContextClassLoader());
    validator = validatorClass.getConstructor().newInstance(); // instantiates!
}
```

`InterceptorDefinition.getInterceptorClass()` similarly loads arbitrary
classes:

```java
// PoolProperties.java:724-747
public Class<? extends JdbcInterceptor> getInterceptorClass() throws ClassNotFoundException {
    if (clazz == null) {
        clazz = ClassLoaderUtil.loadClass(getClassName(), ...);
    }
    return (Class<? extends JdbcInterceptor>) clazz;
}
```

### toString() Reflection Pattern

`PoolProperties.toString()` uses reflection to invoke all property getter
methods on itself:

```java
// PoolProperties.java:601-637
public String toString() {
    for (String field : DataSourceFactory.ALL_PROPERTIES) {
        Method m = getClass().getMethod("get" + capitalize(field));
        buf.append(m.invoke(this, new Object[0])); // calls ALL getters
    }
}
```

This is relevant as a gadget intermediate - if `toString()` is triggered
(e.g., via `BadAttributeValueExpException` from JDK), all getters execute.

---

## Composite Gadget Chain: EL Expression RCE

The most powerful chain combines findings 1, 2, and 4:

```
[Attack Surface: Session Replication / Any ObjectInputStream]
  │
  ▼
Deserialize ValueExpressionImpl (Externalizable)
  ├── readExternal():
  │   ├── expr = attacker-controlled EL string
  │   ├── expectedType = ReflectionUtil.forName(type) → Class.forName(type, true, cl)
  │   ├── fnMapper = FunctionMapperImpl (deserialized)
  │   │   └── functions = ConcurrentHashMap<String, Function>
  │   │       └── Function.readExternal():
  │   │           ├── owner = "java.lang.Runtime" (or any class)
  │   │           ├── name = "exec"
  │   │           └── types = ["java.lang.String"]
  │   └── varMapper = VariableMapperImpl (deserialized)
  │
  ▼ [Post-deserialization trigger needed]
  │
  getValue(ELContext) or via session attribute listener callback
  │
  ├── getNode() → ExpressionBuilder.createNode(expr) → parses EL AST
  ├── node.getValue(ctx) → evaluates expression
  │   └── fnMapper.resolveFunction("fn", "exec")
  │       └── Function.getMethod()
  │           ├── ReflectionUtil.forName("java.lang.Runtime")
  │           ├── Runtime.class.getMethod("exec", String.class)
  │           └── returns Method handle
  └── Expression evaluator invokes method → Runtime.exec("cmd")
```

### Key Observations

1. The `readExternal()` on EL classes performs `Class.forName` with
   `initialize=true` immediately during deserialization
2. The `FunctionMapper` stores arbitrary class/method references as strings
   with zero validation
3. `ReflectionUtil.forName()` has no whitelist - loads any class on classpath
4. Session replication provides a direct, unfiltered deserialization surface
5. The `ReplicationStream` applies no `ObjectInputFilter`

---

## Files of Interest

| File | Gadget Role |
|------|------------|
| `java/org/apache/el/ValueExpressionImpl.java` | Entry point (Externalizable, hashCode triggers parse) |
| `java/org/apache/el/MethodExpressionImpl.java` | Entry point (Externalizable, invoke() triggers eval) |
| `java/org/apache/el/lang/FunctionMapperImpl.java` | Chain link (stores arb class/method as strings) |
| `java/org/apache/el/util/ReflectionUtil.java` | Sink (Class.forName with no filter) |
| `java/org/apache/el/lang/ExpressionBuilder.java` | Parser (createNode parses, build() resolves functions) |
| `java/org/apache/el/lang/VariableMapperImpl.java` | Chain link (stores ValueExpression objects) |
| `java/org/apache/el/ValueExpressionLiteral.java` | Chain link (hashCode delegates to value.hashCode()) |
| `java/org/apache/catalina/ha/session/DeltaSession.java` | Attack surface (unfiltered deser + callbacks) |
| `java/org/apache/catalina/session/StandardSession.java` | Attack surface (attribute deser + callbacks) |
| `java/org/apache/catalina/tribes/io/ReplicationStream.java` | Attack surface (no ObjectInputFilter) |
| `java/org/apache/tomcat/dbcp/dbcp2/datasources/SharedPoolDataSource.java` | JNDI injection (Serializable + lookup) |
| `java/org/apache/tomcat/dbcp/dbcp2/datasources/PerUserPoolDataSource.java` | JNDI injection (Serializable + lookup) |
| `java/org/apache/tomcat/dbcp/dbcp2/datasources/InstanceKeyDataSource.java` | JNDI injection (testCPDS → InitialContext.lookup) |
| `modules/jdbc-pool/src/main/java/org/apache/tomcat/jdbc/pool/PoolProperties.java` | Class instantiation (setValidatorClassName) |
