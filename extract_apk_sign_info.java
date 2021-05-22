
import sun.misc.BASE64Encoder;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;


class ManifestDigest {
    private static final String TAG = "ManifestDigest";

    /** The digest of the manifest in our preferred order. */
    private final byte[] mDigest;

    /** What we print out first when toString() is called. */
    private static final String TO_STRING_PREFIX = "ManifestDigest {mDigest=";

    /** Digest algorithm to use. */
    private static final String DIGEST_ALGORITHM = "SHA-256";

    ManifestDigest(byte[] digest) {
        mDigest = digest;
    }

    static ManifestDigest fromInputStream(InputStream fileIs) {
        if (fileIs == null) {
            return null;
        }

        final MessageDigest md;
        try {
            md = MessageDigest.getInstance(DIGEST_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(DIGEST_ALGORITHM + " must be available",
                    e);
        }

        final DigestInputStream dis = new DigestInputStream(
                new BufferedInputStream(fileIs), md);
        try {
            byte[] readBuffer = new byte[8192];
            while (dis.read(readBuffer, 0, readBuffer.length) != -1) {
                // not using
            }
        } catch (IOException e) {
            // Slog.w(TAG, "Could not read manifest");
            return null;
        } finally {
            // IoUtils.closeQuietly(dis);
        }

        final byte[] digest = md.digest();
        return new ManifestDigest(digest);
    }

    public int describeContents() {
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ManifestDigest)) {
            return false;
        }

        final ManifestDigest other = (ManifestDigest) o;

        return this == other || Arrays.equals(mDigest, other.mDigest);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(mDigest);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(TO_STRING_PREFIX.length()
                + (mDigest.length * 3) + 1);

        sb.append(TO_STRING_PREFIX);

        final int N = mDigest.length;
        for (int i = 0; i < N; i++) {
            final byte b = mDigest[i];
//            IntegralToString.appendByteAsHex(sb, b, false);
            sb.append(',');
        }
        sb.append('}');

        return sb.toString();
    }

}

public class extract_apk_sign_info {
    private String mArchiveSourcePath = "path\\to\\your.apk";

    private java.security.cert.Certificate[] loadCertificates(JarFile jarFile,
                                                              JarEntry je, byte[] readBuffer) {
        try {
            // We must read the stream for the JarEntry to retrieve
            // its certificates.
            InputStream is = new BufferedInputStream(jarFile.getInputStream(je));
            while (is.read(readBuffer, 0, readBuffer.length) != -1) {
            }
            is.close();
            return je != null ? je.getCertificates() : null;
        } catch (IOException e) {
            System.out.print(e.toString());
        } catch (RuntimeException e) {
            System.out.print(e.toString());
        }
        return null;
    }

    private static final String ANDROID_MANIFEST_FILENAME = "AndroidManifest.xml";
    public ArrayList<byte[]> mSignatures;
    public ManifestDigest manifestDigest;

    public boolean collectCertificates() {
        byte[] readBuffer = new byte[8192];
        java.security.cert.Certificate[] certs = null;
        try {
            JarFile jarFile = new JarFile(mArchiveSourcePath);

            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                final JarEntry je = entries.nextElement();
                if (je.isDirectory())
                    continue;
                final String name = je.getName();
                if (name.contains("RSA")) {
                    int a = 0;
                    a++;

                }
                if (name.startsWith("META-INF/"))
                    continue;

                if (ANDROID_MANIFEST_FILENAME.equals(name)) {
                    manifestDigest = ManifestDigest.fromInputStream(jarFile
                            .getInputStream(je));
                }

                final Certificate[] localCerts = loadCertificates(jarFile, je,
                        readBuffer);

                if (localCerts == null) {
                    System.out.print("localCerts is null");
                    jarFile.close();
                    return false;
                } else if (certs == null) {
                    certs = localCerts;
                } else {
                    // Ensure all certificates match.
                    for (int i = 0; i < certs.length; i++) {
                        boolean found = false;
                        for (int j = 0; j < localCerts.length; j++) {
                            if (certs[i] != null
                                    && certs[i].equals(localCerts[j])) {
                                found = true;
                                break;
                            }
                        }
                        if (!found || certs.length != localCerts.length) {
                            System.out.print(" Package "
                                    + " has mismatched certificates at entry "
                                    + je.getName() + "; ignoring!");
                            jarFile.close();
                            return false;
                        }
                    }
                }
            }

            jarFile.close();

            if (certs != null && certs.length > 0) {
                mSignatures = new ArrayList();
                for (int i = 0; i < certs.length; i++) {
                    mSignatures.add(certs[i].getEncoded());
                }
            } else {
                System.out.print("Package " + " has no certificates; ignoring!");
                return false;
            }

            BASE64Encoder Base64 = new BASE64Encoder();
            // Add the signing KeySet to the system
            mSigningKeys = new HashSet<PublicKey>();
            for (int i = 0; i < certs.length; i++) {
                mSigningKeys.add(certs[i].getPublicKey());
                System.out.println("PublicKey"+i+": \n" + Base64.encode(certs[i].getPublicKey().getEncoded()));
                System.out.println("Cert"+i+": \n" + certs[i].toString());
            }

        } catch (Exception e) {
            System.out.print(e.toString());
            return false;
        }
        return true;
    }

    public Set<PublicKey> mSigningKeys;

    public static void main(String[] args) {
        extract_apk_sign_info t = new extract_apk_sign_info();
        t.collectCertificates();
    }
}
