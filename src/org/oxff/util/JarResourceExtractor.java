package org.oxff.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarResourceExtractor {

    public static void extractResourcesTo(String targetDir) throws IOException {
        File jarFile = new File(JarResourceExtractor.class.getProtectionDomain().getCodeSource().getLocation().getPath());
        JarFile jar = new JarFile(jarFile);
        Enumeration<JarEntry> enumEntries = jar.entries();

        Path targetPath = Paths.get(targetDir);

        while (enumEntries.hasMoreElements()) {
            JarEntry entry = enumEntries.nextElement();
            if (entry.getName().startsWith("interActiveHTMLReport/")) { // Assumes your files are in the "dist/" directory inside JAR
                Path entryDestination = targetPath.resolve(entry.getName());

                if (entry.isDirectory()) {
                    Files.createDirectories(entryDestination);
                } else {
                    ensureParentDirectoryExists(entryDestination);
                    try (InputStream is = jar.getInputStream(entry); FileOutputStream fos = new FileOutputStream(entryDestination.toFile())) {
                        byte[] buffer = new byte[1024];
                        int length;
                        while ((length = is.read(buffer)) > 0) {
                            fos.write(buffer, 0, length);
                        }
                    }
                }
            }
        }
        jar.close();
    }

    private static void ensureParentDirectoryExists(Path path) throws IOException {
        if (path.getParent() != null && !Files.exists(path.getParent())) {
            Files.createDirectories(path.getParent());
        }
    }

//    public static void main(String[] args) {
//        try {
//            extractResourcesTo("path/to/target/directory"); // Replace with the path to your target directory
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
}
