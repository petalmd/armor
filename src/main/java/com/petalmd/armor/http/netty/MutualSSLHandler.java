/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * Copyright 2015 PetalMD
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.petalmd.armor.http.netty;

import java.net.SocketAddress;
import java.security.Principal;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.ssl.SslHandler;

public class MutualSSLHandler extends SimpleChannelHandler {

    MutualSSLHandler() {
        super();
    }

    private static class MessageEventFacade implements MessageEvent {

        private final MessageEvent inner;
        private final Object message;

        MessageEventFacade(final MessageEvent inner, final Object message) {
            super();
            this.inner = inner;
            this.message = message;
        }

        @Override
        public Channel getChannel() {
            return inner.getChannel();
        }

        @Override
        public ChannelFuture getFuture() {
            return inner.getFuture();
        }

        @Override
        public Object getMessage() {
            return message;
        }

        @Override
        public SocketAddress getRemoteAddress() {
            return inner.getRemoteAddress();
        }

    }

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) throws Exception {
        final Object o = e.getMessage();
        if (o instanceof DefaultHttpRequest) {

            final SslHandler sslhandler = (SslHandler) e.getChannel().getPipeline().get("ssl_http");
            final Principal principal = sslhandler.getEngine().getSession().getPeerCertificateChain()[0].getSubjectDN();
            final DefaultHttpRequest request = (DefaultHttpRequest) o;
            final DefaultHttpsRequest httpsRequest = new DefaultHttpsRequest(request, principal);
            final MessageEventFacade facade = new MessageEventFacade(e, httpsRequest);
            super.messageReceived(ctx, facade);

        } else {

            super.messageReceived(ctx, e);

        }
    }

    public static class DefaultHttpsRequest extends DefaultHttpRequest {

        private final Principal principal;

        public DefaultHttpsRequest(final DefaultHttpRequest inner, final Principal principal) {
            super(inner.getProtocolVersion(), inner.getMethod(), inner.getUri());
            this.principal = principal;
            this.setChunked(inner.isChunked());
            this.setContent(inner.getContent());
            this.headers().add(inner.headers());
        }

        public Principal getPrincipal() {
            return principal;
        }

    }

}
