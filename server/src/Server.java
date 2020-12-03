
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

public class Server implements Runnable {
    private ArrayList<ChatServerThread> clientList = new ArrayList<ChatServerThread>();
    private ChatServerThread clients[] = new ChatServerThread[50];
    private ServerSocket server = null;
    private Thread thread = null;
    private int clientCount = 0;
    private String randomKeyForAES;
    private  String randomKeyForDES;

    public Server(int port, String randomKeyForAES, String randomKeyForDES)  {
        this.randomKeyForAES = randomKeyForAES;
        this.randomKeyForDES = randomKeyForDES;
        try {
            System.out.println("Binding to port " + port + ", please wait  ...");
            server = new ServerSocket(port);
            System.out.println("Server started: " + server);
            start();
        } catch (IOException ioe) {
            System.out.println("Can not bind to port " + port + ": " + ioe.getMessage());
        }

    }

    public void run() {
        while (thread != null) {
            try {
                System.out.println("Waiting for a client ...");

                addThread(server.accept());



            } catch (IOException ioe) {
                System.out.println("Server accept error: " + ioe);
                stop();
            }
        }
    }

    public void start() {
        if (thread == null) {
            thread = new Thread(this);
            thread.start();
        }
    }

    public void stop() {
        if (thread != null) {
            thread.stop();
            thread = null;
        }
    }

    private int findClient(int ID) {
        for (int i = 0; i < clientCount; i++)
            if (clientList.get(i).getID() == ID)
                return i;
        return -1;
    }

    public synchronized void handle(int ID, String input) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter("logs.txt", true));
        if (input.equals("exit")) {
            clientList.get(findClient(ID)).send("left");
            writer.append(clientList.get(findClient(ID))+"left\n");
            remove(ID);
        } else
            for (int i = 0; i < clientCount; i++) {
                int index = input.indexOf(">");
                String name = input.substring(0,index+1);
                String msg = input.substring(index+1,input.length());
                clientList.get(i).send(name + ": " + msg);
                writer.append(msg + "   this message send to  "  + clientList.get(i) );
                writer.append("\n" );

            }
        writer.close();

    }

    public synchronized void remove(int ID) {
        int pos = findClient(ID);
        if (pos >= 0) {
            ChatServerThread toTerminate = clientList.get(pos);
            System.out.println("Removing client thread " + ID + " at " + pos);
            clientList.remove(pos);
            clientCount--;
            try {
                toTerminate.close();
            } catch (IOException ioe) {
                System.out.println("Error closing thread: " + ioe);
            }
            toTerminate.stop();
        }
    }

    private void addThread(Socket socket) throws IOException {
        FileWriter myWriter = new FileWriter("logs.txt",true);

        System.out.println("Client accepted: " + socket);
        myWriter.write("Client accepted: " + socket);
        myWriter.write("\n");

        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(randomKeyForAES);
        DataOutputStream outiv = new DataOutputStream(socket.getOutputStream());
        outiv.writeUTF(randomKeyForAES);
        ChatServerThread newClient = new ChatServerThread(this, socket);

        clientList.add(newClient);
        try {
            newClient.open();
            newClient.start();
            clientCount++;
        } catch (IOException ioe) {
            System.out.println("Error opening thread: " + ioe);
        }
        myWriter.close();

    }
    private static String generateRandomKey() {

        StringBuilder randomKey = new StringBuilder();
        for (int i = 0; i < 64; i++) {
            if ((int) (Math.random() * i) % 2 == 0) {
                randomKey.append("0");
            } else {
                randomKey.append("1");
            }
        }
        return randomKey.toString();
    }

    public static void main(String args[]) {
        String key = generateRandomKey();
        String iv = generateRandomKey();
        int port = 9090;
        new Server(port,key,iv);

    }

}

class ChatServerThread extends Thread {
    private Server server = null;
    private Socket socket = null;
    private int ID = -1;
    private DataInputStream streamIn = null;
    private DataOutputStream streamOut = null;

    public ChatServerThread(Server _server, Socket _socket) {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();
    }

    public void send(String msg) {
        try {
            streamOut.writeUTF(msg);
            streamOut.flush();
        } catch (IOException ioe) {
            System.out.println(ID + " ERROR sending: " + ioe.getMessage());
            server.remove(ID);
            stop();
        }
    }

    public int getID() {
        return ID;
    }

    public void run() {
        System.out.println("Server Thread " + ID + " running.");
        while (true) {
            try {
                server.handle(ID, streamIn.readUTF());
            } catch (IOException ioe) {
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            }
        }
    }

    public void open() throws IOException {
        streamIn = new DataInputStream(new
                BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new
                BufferedOutputStream(socket.getOutputStream()));
    }

    public void close() throws IOException {
        if (socket != null) socket.close();
        if (streamIn != null) streamIn.close();
        if (streamOut != null) streamOut.close();
    }
}

