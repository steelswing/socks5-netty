
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.ByteToMessageDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Socks5ProxyServer {

    private final int port;
    protected String host;
    private final Map<String, String> users;

    public Socks5ProxyServer(String host, int port) {
        this.host = host;
        this.port = port;
        this.users = new HashMap<>();
        // users
        users.put("login", "password");
    }

    public void start() throws Exception {
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();

        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(new Socks5Handler(users));
                        }
                    });

            ChannelFuture f = b.bind(host, port).sync();
            System.out.println("SOCKS5 Proxy Server запущен на порту " + port);
            f.channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Host: " + args[0] + ":" + args[1]);
        new Socks5ProxyServer(args[0], Integer.parseInt(args[1])).start();
    }
}

class Socks5Handler extends ByteToMessageDecoder {

    private enum State {
        INIT, AUTH, CONNECT, RELAY
    }

    private State state = State.INIT;
    private final Map<String, String> users;
    private Channel remoteChannel;

    public Socks5Handler(Map<String, String> users) {
        this.users = users;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        switch (state) {
            case INIT:
                handleInit(ctx, in);
                break;
            case AUTH:
                handleAuth(ctx, in);
                break;
            case CONNECT:
                handleConnect(ctx, in);
                break;
            case RELAY:
                // Данные просто пересылаются
                break;
        }
    }

    private void handleInit(ChannelHandlerContext ctx, ByteBuf in) {
        if (in.readableBytes() < 2) {
            return;
        }

        byte version = in.readByte();
        byte nMethods = in.readByte();

        if (version != 0x05) {
            ctx.close();
            return;
        }

        if (in.readableBytes() < nMethods) {
            in.readerIndex(in.readerIndex() - 2);
            return;
        }

        boolean hasAuth = false;
        for (int i = 0; i < nMethods; i++) {
            if (in.readByte() == 0x02) { // USERNAME/PASSWORD auth
                hasAuth = true;
            }
        }

        ByteBuf response = Unpooled.buffer(2);
        response.writeByte(0x05); // SOCKS version
        response.writeByte(hasAuth ? 0x02 : 0xFF); // Method: auth required or no acceptable

        ctx.writeAndFlush(response);

        if (hasAuth) {
            state = State.AUTH;
        } else {
            ctx.close();
        }
    }

    private void handleAuth(ChannelHandlerContext ctx, ByteBuf in) {
        if (in.readableBytes() < 2) {
            return;
        }

        byte version = in.readByte();
        int uLen = in.readUnsignedByte();

        if (in.readableBytes() < uLen + 1) {
            in.readerIndex(in.readerIndex() - 2);
            return;
        }

        String username = in.readCharSequence(uLen, StandardCharsets.UTF_8).toString();
        int pLen = in.readUnsignedByte();

        if (in.readableBytes() < pLen) {
            in.readerIndex(in.readerIndex() - 2 - uLen - 1);
            return;
        }

        String password = in.readCharSequence(pLen, StandardCharsets.UTF_8).toString();

        boolean authSuccess = users.containsKey(username) && users.get(username).equals(password);

        ByteBuf response = Unpooled.buffer(2);
        response.writeByte(0x01); // Auth version

        if (authSuccess) {
            response.writeByte(0x00); // Success
            state = State.CONNECT;
            System.out.println("Пользователь " + username + " авторизован");
        } else {
            response.writeByte(0x01); // Failure
            System.out.println("Неудачная авторизация: " + username);
        }

        ctx.writeAndFlush(response).addListener((ChannelFutureListener) future -> {
            if (!authSuccess) {
                ctx.close();
            }
        });
    }

    private void handleConnect(ChannelHandlerContext ctx, ByteBuf in) {
        if (in.readableBytes() < 4) {
            return;
        }

        byte version = in.readByte();
        byte cmd = in.readByte();
        byte rsv = in.readByte();
        byte atyp = in.readByte();

        if (cmd != 0x01) { // Только CONNECT поддерживается
            sendConnectResponse(ctx, (byte) 0x07); // Command not supported
            return;
        }

        String host;
        int port;

        try {
            if (atyp == 0x01) { // IPv4
                if (in.readableBytes() < 6) {
                    in.readerIndex(in.readerIndex() - 4);
                    return;
                }
                host = String.format("%d.%d.%d.%d",
                        in.readUnsignedByte(), in.readUnsignedByte(),
                        in.readUnsignedByte(), in.readUnsignedByte());
                port = in.readUnsignedShort();
            } else if (atyp == 0x03) { // Domain
                if (in.readableBytes() < 1) {
                    in.readerIndex(in.readerIndex() - 4);
                    return;
                }
                int len = in.readUnsignedByte();
                if (in.readableBytes() < len + 2) {
                    in.readerIndex(in.readerIndex() - 5);
                    return;
                }
                host = in.readCharSequence(len, StandardCharsets.UTF_8).toString();
                port = in.readUnsignedShort();
            } else {
                sendConnectResponse(ctx, (byte) 0x08); // Address type not supported
                return;
            }
        } catch (Exception e) {
            sendConnectResponse(ctx, (byte) 0x01);
            return;
        }

        connectToRemote(ctx, host, port);
    }

    private void connectToRemote(ChannelHandlerContext ctx, String host, int port) {
        Bootstrap b = new Bootstrap();
        b.group(ctx.channel().eventLoop())
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new RelayHandler(ctx.channel()));
                    }
                });

        System.out.println("Подключение к " + host + ":" + port);

        ChannelFuture f = b.connect(host, port);
        remoteChannel = f.channel();

        f.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                sendConnectResponse(ctx, (byte) 0x00); // Success
                ctx.pipeline().remove(Socks5Handler.this);
                ctx.pipeline().addLast(new RelayHandler(remoteChannel));
                state = State.RELAY;
            } else {
                sendConnectResponse(ctx, (byte) 0x05); // Connection refused
                ctx.close();
            }
        });
    }

    private void sendConnectResponse(ChannelHandlerContext ctx, byte status) {
        ByteBuf response = Unpooled.buffer();
        response.writeByte(0x05); // SOCKS version
        response.writeByte(status);
        response.writeByte(0x00); // Reserved
        response.writeByte(0x01); // IPv4
        response.writeInt(0); // 0.0.0.0
        response.writeShort(0); // Port 0

        ctx.writeAndFlush(response);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (remoteChannel != null && remoteChannel.isActive()) {
            remoteChannel.close();
        }
    }
}

class RelayHandler extends ChannelInboundHandlerAdapter {

    private final Channel relayChannel;

    public RelayHandler(Channel relayChannel) {
        this.relayChannel = relayChannel;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (relayChannel.isActive()) {
            relayChannel.writeAndFlush(msg);
        } else {
            ((ByteBuf) msg).release();
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (relayChannel.isActive()) {
            relayChannel.close();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}
