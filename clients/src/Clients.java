import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;


class Client implements Runnable {
    private Socket socket = null;
    private Thread thread = null;
    private DataInputStream console = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client = null;
    private String user_name;
    private String key;
    private String iv;
    public String outputString;
    public String sendFlag = null;
    public String msgBased64 = null;
    public JTextArea chatarea;
    private boolean aes_des_method = true;
    private boolean cbc_ofb_mode = true;


    public Client(String serverName, int serverPort, String name, JTextArea chatarea) {
        System.out.println("Start connection......");
        this.chatarea = chatarea;
        try {
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected: " + socket);
            user_name = name;

            DataInputStream radomkey = new DataInputStream(socket.getInputStream());
            key = radomkey.readUTF();
            System.out.println("Key from server: " + key);
            DataInputStream radomIv = new DataInputStream(socket.getInputStream());
            iv = radomkey.readUTF();
            System.out.println("IV" + iv);
            System.out.println("welcome, you can start chatting\n");

            start();
        } catch (UnknownHostException uhe) {
            System.out.println("Host unknown: " + uhe.getMessage());
        } catch (IOException ioe) {
            System.out.println("Unexpected exception: " + ioe.getMessage());
        }
    }

    public void sendMsg() {
        this.sendFlag = "send my message";
    }

    public String getMsgBased64() {
        return msgBased64;
    }

    public void setMsgBased64(String message) {
        try {
            this.msgBased64 = encrptionOptions(user_name + " sent -> " + message, key, iv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void setAes_des_method(boolean aes_des_method) {
        this.aes_des_method = aes_des_method;
    }

    public void setCbc_ofb_mode(boolean cbc_ofb_mode) {
        this.cbc_ofb_mode = cbc_ofb_mode;
    }

    public boolean getAes_des_method() {
        return aes_des_method;
    }

    public boolean getCbc_ofb_mode() {
        return cbc_ofb_mode;
    }

    public String getOutputString() {
        if (outputString != null) {
            String val = outputString;
            outputString = null;
            return val;
        }
        return outputString;
    }

    public void run() {
        while (thread != null) {
            try {
                this.sendFlag = this.sendFlag;
                if (sendFlag != null) {
                    streamOut.writeUTF(msgBased64);
                    //streamOut.writeUTF(user_name +" sent -> "+ msg);
                    streamOut.flush();
                    this.sendFlag = null;
                }
            } catch (IOException ioe) {
                System.out.println("Sending error: " + ioe.getMessage());
                stop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private String decreptionOptions(String cipherText, String key, String iv) throws Exception {
        if (aes_des_method) {
            if (cbc_ofb_mode) {
                key = key.substring(0, 16);
                iv = iv.substring(0, 16);
            } else {
                key = key.substring(0, 8);
                iv = iv.substring(0, 8);
            }
        } else {
            iv = iv.substring(0, 8);
            key = key.substring(0, 8);
        }


        EncDec encObj = null;
        if (aes_des_method && cbc_ofb_mode) {
            encObj = new EncDec(key, iv, "AES", "CBC");
        } else if (aes_des_method && !cbc_ofb_mode) {
            encObj = new EncDec(key, iv, "DES", "OFB");
        } else if (!aes_des_method && cbc_ofb_mode) {
            encObj = new EncDec(key, iv, "DES", "CBC");
        } else if (!aes_des_method && !cbc_ofb_mode) {
            encObj = new EncDec(key, iv, "DES", "OFB");
        }

        String desDecryption = encObj.decrypt(cipherText);
        System.out.println("After decryption - " + cipherText);
        String output = new String(Base64.getEncoder().encode(cipherText.getBytes()));
        System.out.println(output);
        return new String(desDecryption);
    }


    private String encrptionOptions(String plaintext, String key, String iv) throws Exception {

        if (aes_des_method) {
            if (cbc_ofb_mode) {
                key = key.substring(0, 16);
                iv = iv.substring(0, 16);
            } else {
                key = key.substring(0, 8);
                iv = iv.substring(0, 8);
            }

        } else {
            iv = iv.substring(0, 8);
            key = key.substring(0, 8);
        }

        EncDec encObj = null;
        if (aes_des_method && cbc_ofb_mode) {
            encObj = new EncDec(key, iv, "AES", "CBC");
        } else if (aes_des_method && !cbc_ofb_mode) {
            encObj = new EncDec(key, iv, "DES", "OFB");
        } else if (!aes_des_method && cbc_ofb_mode) {
            encObj = new EncDec(key, iv, "DES", "CBC");
        } else if (!aes_des_method && !cbc_ofb_mode) {
            encObj = new EncDec(key, iv, "DES", "OFB");
        }

        String desEncryption = encObj.encrypt(plaintext);
        System.out.println(desEncryption);

        return new String(desEncryption);
    }

    public void handle(String msg) {
        if (msg.equals("exit")) {
            System.out.println("Good bye. Press RETURN to exit ...");
            stop();
        } else {
            try {
                String decMsg = decreptionOptions(msg, key, iv);
                chatarea.append(msg + "\n" + decMsg + "\n");
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
    }

    public void start() throws IOException {
        console = new DataInputStream(System.in);
        System.out.println("consule" + console.toString());
        streamOut = new DataOutputStream(socket.getOutputStream());
        if (thread == null) {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    public void stop() {
        if (thread != null) {
            thread.stop();
            thread = null;
        }
        try {
            if (console != null) console.close();
            if (streamOut != null) streamOut.close();
            if (socket != null) socket.close();
        } catch (IOException ioe) {
            System.out.println("Error closing ...");
        }
        client.close();
        client.stop();
    }
}


class EncDec {
    private static String initVector;
    private static Key key;
    private static final String characterEncoding = "UTF-8";
    private final String PADDING_SCHEME = "PKCS5Padding";

    private final String Method;
    private final String Mode;
    byte[] ivBytes = new byte[8];
    private final String keystring;
    String transformation;

    public EncDec(String key, String iv, String method, String mode) {
        this.ivBytes = iv.getBytes();
        this.Method = method;
        this.Mode = mode;
        this.keystring = key;
        this.initVector = iv;
        this.key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), Method);
        transformation = String.format("%s/%s/%s", Method, Mode, PADDING_SCHEME);
    }

    public String encrypt(String valueToEncrypt) throws Exception {
        if (Method.equals("AES")) {
            return encryptAES(valueToEncrypt);
        } else {
            return encryptDES(valueToEncrypt);
        }
    }

    public String decrypt(String valueToEncrypt) throws Exception {
        if (Method.equals("AES")) {
            return decryptAES(valueToEncrypt);
        } else {
            return decryptDES(valueToEncrypt);
        }
    }


    public String encryptDES(String valueToEncrypt) throws Exception {
        Cipher instance = Cipher.getInstance(transformation);
        instance.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] bytes = instance.doFinal(String.format("12345678%s", valueToEncrypt).getBytes());
        return Base64.getEncoder().encodeToString(bytes);
    }

    public String decryptDES(String encryptedValue) throws Exception {
        transformation = String.format("%s/%s/%s", Method, Mode, PADDING_SCHEME);
        Cipher instance = Cipher.getInstance(transformation);
        instance.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] bytes = instance.doFinal(Base64.getMimeDecoder().decode(encryptedValue));
        return new String(bytes, StandardCharsets.UTF_8).substring(8);
    }

    public String encryptAES(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(characterEncoding));

            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String decryptAES(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(characterEncoding));
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] original = cipher.doFinal(Base64.getMimeDecoder().decode(ciphertext));
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}


class ChatClientThread extends Thread {
    private Socket socket = null;
    private Client client = null;
    private DataInputStream streamIn = null;

    public ChatClientThread(Client _client, Socket _socket) {
        client = _client;
        socket = _socket;
        open();
        start();
    }

    public void open() {
        try {
            streamIn = new DataInputStream(socket.getInputStream());
        } catch (IOException ioe) {
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }

    public void close() {
        try {
            if (streamIn != null) streamIn.close();
        } catch (IOException ioe) {
            System.out.println("Error closing input stream: " + ioe);
        }
    }

    public void run() {
        while (true) {
            try {
                client.handle(streamIn.readUTF());
            } catch (IOException ioe) {
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
        }
    }
}

public class Clients {
    static boolean connected = false;
    static boolean disconnected = false;
    //    static  boolean aes =
    static String user_name = "";
    static Client cli = null;
    static boolean aes_des = true;
    static boolean cbc_ofb = true;

    public static void main(String[] args) {
        JFrame frame = new JFrame("Crypt Messenger");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1000, 1000);
        Font font = new Font("Calibri", 1, 14);
        frame.setFont(font);
        frame.setResizable(true);
        frame.setIconImage(new ImageIcon("logo.png").getImage());

        JPanel panel = new JPanel(); // the panel is not visible in output
        JButton connectButton = new JButton("Connect", new ImageIcon("play-solid.png"));
        JButton disconnectButton = new JButton("Disconnect", new ImageIcon("stop-solid.png"));
        System.out.println(connectButton.getText());


        JPanel methodPanel = new JPanel();
        methodPanel.setBorder(BorderFactory.createTitledBorder("Method"));
        methodPanel.setLayout(new GridBagLayout());
        JRadioButton aesRadioButton = new JRadioButton("AES");
        JRadioButton desRadioButton = new JRadioButton("DES");
        methodPanel.add(aesRadioButton);
        methodPanel.add(desRadioButton);
        aesRadioButton.setSelected(aes_des);
        JPanel modePanel = new JPanel();
        modePanel.setBorder(BorderFactory.createTitledBorder("Mode"));
        modePanel.setLayout(new GridBagLayout());
        JRadioButton cbcRadioButton = new JRadioButton("CBC");
        JRadioButton ofbRadioButton = new JRadioButton("OFB");
        modePanel.add(cbcRadioButton);
        modePanel.add(ofbRadioButton);
        cbcRadioButton.setSelected(cbc_ofb);
        disconnectButton.setEnabled(false);
        panel.add(connectButton);
        panel.add(disconnectButton);
        panel.add(methodPanel);
        panel.add(modePanel);
        panel.setFont(font);

        //Creating the panel at bottom and adding components
        JPanel panel2 = new JPanel(); // the panel is not visible in output

        JPanel plainTextPanel = new JPanel();
        plainTextPanel.setBorder(BorderFactory.createTitledBorder("Text"));
        plainTextPanel.setLayout(new GridBagLayout());
        JTextArea textArea = new JTextArea(5, 25);
        textArea.setLineWrap(true);
        plainTextPanel.add(textArea);

        JPanel cipherTextPanel = new JPanel();
        cipherTextPanel.setBorder(BorderFactory.createTitledBorder("Crypted Text"));
        cipherTextPanel.setLayout(new GridBagLayout());
        JTextArea cryptedTextArea = new JTextArea(5, 25);
        textArea.setLineWrap(true);
        cipherTextPanel.add(cryptedTextArea);

        panel2.add(BorderLayout.NORTH, plainTextPanel);
        panel2.add(BorderLayout.NORTH, cipherTextPanel);

        JButton encyrptButton = new JButton("Encrypt", new ImageIcon("lock-solid.png"));
        JButton sendButton = new JButton("Send", new ImageIcon("paper-plane-solid.png"));
        encyrptButton.setEnabled(false);
        sendButton.setEnabled(false);
        JLabel statlabel = new JLabel("Not Connected");

        panel2.add(BorderLayout.NORTH, encyrptButton);
        panel2.add(BorderLayout.NORTH, sendButton);
        panel2.add(BorderLayout.SOUTH, statlabel);
        panel2.setFont(font);

        // Text Area at the Center
        JTextArea chatArea = new JTextArea();
        chatArea.setFont(font);
        chatArea.setAutoscrolls(true);
        chatArea.setLineWrap(true);

        //Adding Components to the frame.
        frame.getContentPane().add(BorderLayout.NORTH, panel);
        frame.getContentPane().add(BorderLayout.CENTER, chatArea);
        frame.getContentPane().add(BorderLayout.SOUTH, panel2);
        frame.setVisible(true);

        aesRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                aes_des = aesRadioButton.isSelected();
                desRadioButton.setSelected(!aes_des);
                cli.setAes_des_method(aes_des);
            }
        });

        desRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                aes_des = !desRadioButton.isSelected();
                aesRadioButton.setSelected(aes_des);
                cli.setAes_des_method(aes_des);
            }
        });

        cbcRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cbc_ofb = cbcRadioButton.isSelected();
                ofbRadioButton.setSelected(!cbc_ofb);
                cli.setCbc_ofb_mode(cbc_ofb);
            }
        });

        ofbRadioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cbc_ofb = !ofbRadioButton.isSelected();
                cbcRadioButton.setSelected(cbc_ofb);
                cli.setCbc_ofb_mode(cbc_ofb);
            }
        });

        connectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                disconnectButton.setEnabled(true);
                connectButton.setEnabled(false);
                encyrptButton.setEnabled(true);
                user_name = JOptionPane.showInputDialog(frame, "Enter username:");
                cli = new Client("localhost", 9090, user_name, chatArea);
                statlabel.setText("Connected: " + user_name);
            }
        });

        disconnectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                disconnectButton.setEnabled(false);
                connectButton.setEnabled(true);
                encyrptButton.setEnabled(false);
                statlabel.setText("Not Connected");
                cli.stop();
            }
        });

        encyrptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendButton.setEnabled(true);
                cli.setMsgBased64(textArea.getText());
                cryptedTextArea.setText(cli.getMsgBased64());
            }
        });

        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cli.sendMsg();
            }
        });

    }
}

