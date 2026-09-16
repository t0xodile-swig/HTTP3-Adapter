# HTTP/3-Adapter

A Burp Suite extension that sends requests over **HTTP/3**.

Burp does not support HTTP/3 natively. This extension implements a HTTP/3 stack, intercepts all requests, converts and sends them over HTTP/3 and then converts the response back into a HTTP version that burp can understand.

## Install

Available in the BAPP Store. 

Build it yourself:

```sh
./gradlew jar     # -> build/libs/HTTP3-Adapter-0.0.1.jar
```

## Send a request over HTTP/3

In `Explicit HTTP/3 only` mode add an `X-Http3` header:

```
GET /admin HTTP/1.1
Host: example.com
X-Http3: 1
```

In `Always HTTP/3 where possible` mode, any traffic will be adapted if application supports HTTP/3

## Check which sites support HTTP/3

If you want to know if multiple hosts in your proxy history support HTTP/3, you can select them and use the `Check HTTP/3 Support` context menu option which reports into organizer. 

## Settings

**Settings -> Extensions -> HTTP/3 Adapter**

| Setting | Default | Notes |
|---|---|---|
| Mode | Explicit HTTP/3 only | Swaps between the two modes mentioned above |
| Handshake timeout (ms) | 10000 |  |
| Request timeout (ms) | 15000 | |
| Reuse connections | on |  |
| Log exchanges to Output | off | Writes each adapted request and response to the Output panel. |
| Show unsupported origins tab | off | See below. |
| Strip `Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`, `Upgrade` | on | HTTP/3 forbids these headers, uncheck to send them deliberately. |
| Verify TLS certificates | off | Matches Burp's own upstream behaviour by default. |

## Unsupported Origins Tab
This tab will show you which hosts failed the HTTP/3 QUIC handshake. You can clear this list to retry if you have an unstable connection. The tab is hidden by default, but can be enabled in the settings panel. 

## Kettled requests

Just as in HTTP/2, requests can be kettled. 

Add an `X-Kettled: 1` header alongside the `X-Http3: 1` header and the header block is sent **exactly as written**. Names keep their case, nothing is stripped, `Host` is not folded into `:authority`, and these escapes are decoded
first:

| Escape | Byte |
|---|---|
| `^~` | CR LF |
| `^r` | CR |
| `^n` | LF |
| `^0` | NULL |
| `^s` | space |
| `^xNN` | any byte, two hex digits |
| `^^` | a literal `^` |

```
POST /x HTTP/1.1
X-Http3: 1
X-Kettled: 1
:method: BREW
content-length: 10
foo: bar^~transfer-encoding:^schunked

0

hello
```

## Limitations

- **Upstream proxies are bypassed.** 
- **Adapted traffic does not appear in Logger.**
