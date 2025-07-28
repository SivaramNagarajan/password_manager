import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

public class passman{

    static class Credential implements Serializable {
        private static final long serialVersionUID = 1L; 
        String site;
        String username;
        String password;

        Credential(String site, String username, String password) {
            this.site = site;
            this.username = username;
            this.password = password;
        }

        @Override
        public String toString() {
            return site + " | " + username + " | " + password;
        }
    }

    static class EncryptionUtil {
        static SecretKey getKey(String password) throws Exception {
            byte[] key = password.getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            key = sha.digest(key);
            return new SecretKeySpec(key, "AES");
        }

        static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        }

        static byte[] decrypt(byte[] data, SecretKey key) throws Exception {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        }
    }

    static class Vault {
        static final String FILE_NAME = System.getProperty("user.home") + File.separator + "vault.dat";

        static void save(List<Credential> creds, SecretKey key) throws Exception {
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(creds);
                byte[] encrypted = EncryptionUtil.encrypt(baos.toByteArray(), key);
                try (FileOutputStream fos = new FileOutputStream(FILE_NAME)) {
                    fos.write(encrypted);
                }
            }
        }

        static List<Credential> load(SecretKey key) throws Exception {
            File file = new File(FILE_NAME);
            if (!file.exists() || file.length() == 0) {
                return new ArrayList<>(); 
            }

            byte[] encrypted;
            try (FileInputStream fis = new FileInputStream(file)) {
                encrypted = fis.readAllBytes(); 
            }

            try {
                byte[] decrypted = EncryptionUtil.decrypt(encrypted, key);
                try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decrypted))) {
                    return (List<Credential>) ois.readObject();
                }
            } catch (Exception e) {
                throw new Exception("Failed to decrypt or deserialize vault. Wrong password or corrupted file.", e);
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame loginFrame = new JFrame("Password Manager");
            JPasswordField passwordField = new JPasswordField(20);
            JButton loginBtn = new JButton("Login");

            JPanel panel = new JPanel();
            panel.add(new JLabel("Master Password:"));
            panel.add(passwordField);
            panel.add(loginBtn);

            loginFrame.add(panel);
            loginFrame.setSize(300, 100);
            loginFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            loginFrame.setVisible(true);

            loginBtn.addActionListener(e -> {
                String master = new String(passwordField.getPassword());
                if (master.isEmpty()) {
                    JOptionPane.showMessageDialog(loginFrame, "Master password cannot be empty.");
                    return;
                }
                try {
                    SecretKey key = EncryptionUtil.getKey(master);
                    loginFrame.dispose();
                    openVaultUI(key);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(loginFrame, "Error: " + ex.getMessage());
                }
            });
        });
    }

    static void openVaultUI(SecretKey key) {
        JFrame vaultFrame = new JFrame("Password Vault");
        DefaultListModel<String> listModel = new DefaultListModel<>();
        JList<String> list = new JList<>(listModel);
        JButton addBtn = new JButton("Add");

        List<Credential> creds;
        try {
            creds = Vault.load(key);
            for (Credential c : creds) {
                listModel.addElement(c.toString());
            }
        } catch (Exception e) {
            creds = new ArrayList<>(); 
            JOptionPane.showMessageDialog(vaultFrame, "Error loading vault: " + e.getMessage());
        }

        
        final List<Credential> finalCreds = creds;
        addBtn.addActionListener(e -> {
            String site = JOptionPane.showInputDialog("Site:");
            String user = JOptionPane.showInputDialog("Username:");
            String pass = JOptionPane.showInputDialog("Password:");

            if (site != null && !site.trim().isEmpty() &&
                user != null && !user.trim().isEmpty() &&
                pass != null && !pass.trim().isEmpty()) {
                Credential c = new Credential(site, user, pass);
                finalCreds.add(c);
                listModel.addElement(c.toString());
                try {
                    Vault.save(finalCreds, key);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(vaultFrame, "Save error: " + ex.getMessage());
                }
            } else {
                JOptionPane.showMessageDialog(vaultFrame, "All fields must be non-empty.");
            }
        });

        vaultFrame.setLayout(new BorderLayout());
        vaultFrame.add(new JScrollPane(list), BorderLayout.CENTER);
        vaultFrame.add(addBtn, BorderLayout.SOUTH);
        vaultFrame.setSize(400, 300);
        vaultFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        vaultFrame.setVisible(true);
    }
}
