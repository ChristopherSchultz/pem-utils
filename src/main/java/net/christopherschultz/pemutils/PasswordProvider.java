package net.christopherschultz.pemutils;

public interface PasswordProvider {
    /**
     * Gets a password for a decryption operation, usually for a private key.
     *
     * This method may be called multiple times by PEMFile.getNext() if the
     * password returned fails to decrypt the Entry. Returning {@code null}
     * indicates that the entry should not be decrypted.
     *
     * @return A password to use to attempt decryption, or {@code null} to
     *         cancel decryption.
     */
    public String getPassword();
}
