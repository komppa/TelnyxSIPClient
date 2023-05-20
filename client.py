import socket
import hashlib
import os
from dotenv import load_dotenv


load_dotenv()


sip_srv_addr = os.getenv("SIP_SRV_ADDR")
sip_srv_port = os.getenv("SIP_SRV_PORT")

sip_username = os.getenv("SIP_USERNAME")
sip_password = os.getenv("SIP_PASSWORD")

phone_number_to_call = ""


# Get custom number to call
custom_number = input(f"Enter number to call or press enter to use default number: {phone_number_to_call}\n")
if (custom_number != ""):
    phone_number_to_call = custom_number



payload = f"REGISTER sip:{sip_srv_addr} SIP/2.0\r\n"
payload += f"Via: SIP/2.0/UDP {sip_srv_addr}:{sip_srv_port};branch=z9hG4bKnashds7\r\n"
payload += f"Max-Forwards: 70\r\n"
payload += f"From: {sip_username} <sip:{sip_username}@{sip_srv_addr}>;tag=a73kszlfl\r\n"
payload += f"To: {sip_username} <sip:{sip_username}@{sip_srv_addr}>\r\n"
payload += f"Call-ID: 1j9FpLxk3uxtm8tn@{sip_srv_addr}\r\n"
payload += f"CSeq: 1 REGISTER\r\n"
payload += f"Contact: <sip:{sip_username}@{sip_srv_addr}>\r\n"
payload += f"Content-Length: 0"
payload += f"\r\n\r\n"


s = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM    
)

s.sendto(
    payload.encode("utf8"),
    (sip_srv_addr, sip_srv_port)
)

recv = s.recv(1024*8)

[headers_raw, body_raw] = recv.split(b"\r\n\r\n")

headers = headers_raw.split(b'\r\n')

def get_nonce_from_headers(headers):
    for h in headers:
        h = h.decode("utf-8")
        if ("nonce" in h):
            # [
            #   'WWW-Authenticate: Digest realm="sip.telnyx.com", ',
            #   '<RANDSTR>",
            #   opaque="2/1.2.3.4"'
            # ]
            attrs = h.split(", ")
            # ['nonce=', '<NONCE>', '']
            for attr in attrs:
                if ("nonce=" in attr):
                    return attr.split("\"")[1]


def get_branch_from_via(headers):
    for h in headers:
        h = h.decode("utf-8")
        if h.startswith("Via: "):
            attrs = h.split(";")
            for attr in attrs:
                if ("branch=" in attr):
                    return attr.split("branch=")[1]


def get_tag_from_from(headers):
    for h in headers:
        h = h.decode("utf-8")
        if h.startswith("From: "):
            attrs = h.split(";")
            for attr in attrs:
                if ("tag=" in attr):
                    return attr.split("tag=")[1]
                
def get_tag_from_to(headers):
    for h in headers:
        h = h.decode("utf-8")
        if h.startswith("From: "):
            attrs = h.split(";")
            for attr in attrs:
                if ("tag=" in attr):
                    return attr.split("tag=")[1]
                
def get_opaque_from_407(headers):
    for h in headers:
        h = h.decode("utf-8")
        if h.startswith("Proxy-Authenticate: "):
            attrs = h.split(",")
            for attr in attrs:
                if ("opaque=" in attr):
                    return attr.split("opaque=")[1][1:-1]   # [1:-1] for removing ""s


def get_auth_response(method, nonce, uri="sip:sip.telnyx.com"):
    ha1_str = f"{sip_username}:sip.telnyx.com:{sip_password}"
    ha1_enc = hashlib.md5(ha1_str.encode()).hexdigest()
    
    ha2_str = f"{method}:{uri}"
    ha2_enc = hashlib.md5(ha2_str.encode()).hexdigest()

    response = f"{ha1_enc}:{nonce}:{ha2_enc}"

    return hashlib.md5(response.encode()).hexdigest()


nonce = get_nonce_from_headers(headers)
response = get_auth_response("REGISTER", nonce)

# TODO currently we asumme that we were required to authenticate
# Reset payload
payload = ""
payload += f"REGISTER sip:{sip_srv_addr} SIP/2.0\r\n"
payload += f"Via: SIP/2.0/UDP {sip_srv_addr}:{sip_srv_port};branch=z9hG4bKnashd92\r\n"
payload += f"Max-Forwards: 70\r\n"
payload += f"From: {sip_username} <sip:{sip_username}@{sip_srv_addr}>;tag=ja743ks76zlflH\r\n"
payload += f"To: {sip_username} <sip:{sip_username}@{sip_srv_addr}>\r\n"
payload += f"Call-ID: 1j9FpLxk3uxtm8tn@{sip_srv_addr}\r\n"
payload += f"CSeq: 2 REGISTER\r\n"
payload += f"Contact: <sip:{sip_username}@{sip_srv_addr}>\r\n"
payload += f'Authorization: Digest username="{sip_username}", realm="sip.telnyx.com", nonce="{nonce}", uri="sip:sip.telnyx.com", response="{response}", algorithm=MD5\r\n' # TODO CRIT opacue removed
payload += f"Content-Length: 0"
payload += f"\r\n\r\n"


s.sendto(
    payload.encode("utf8"),
    (sip_srv_addr, sip_srv_port)
)

recv = s.recv(1024 * 8)


body = ""
body += f"v=0\r\n"
body += f"o=TelnyxSIPClient 1 3 IN IP4 {my_ip}\r\n"
body += f"s=TelnyxSIPClient 1.0.0\r\n"
body += f"c=IN IP4 {my_ip}\r\n"
body += f"t=0 0\r\n"
body += f"m=audio 10926 RTP/AVP 0 101\r\n"
body += f"a=rtpmap:0 PCMU/8000\r\n"
body += f"a=rtpmap:101 telephone-event/8000\r\n"
body += f"a=fmtp:101 0-15\r\n"
body += f"a=ptime:20\r\n"
body += f"a=maxptime:150\r\n"
body += f"a=sendrecv\r\n"


payload = ""
payload += f"INVITE sip:{sip_srv_addr} SIP/2.0\r\n"
payload += f"Via: SIP/2.0/UDP {sip_srv_addr}:{sip_srv_port};branch=z9hG4bK721e.3\r\n"
payload += f"Max-Forwards: 70\r\n"
payload += f"Contact: <sip:{sip_username}@{my_ip}>\r\n"

payload += f"To: <sip:{phone_number_to_call}@{sip_srv_addr}>\r\n"
payload += f"From: <sip:{sip_username}@{my_ip}>;tag=9fxced76sl\r\n"

payload += f"Call-ID: 2xTb9vxSit55XU7p9@{sip_srv_addr}:{sip_srv_port}\r\n"
payload += f"Content-Type: application/sdp\r\n"

payload += f"CSeq: 1 INVITE\r\n"
payload += f"Content-Length: {len(body)}"
payload += f"\r\n\r\n"

payload += f"{body}"


s.sendto(
    payload.encode("utf8"),
    (sip_srv_addr, sip_srv_port)
)


# 100 Telnyx trying
recv = s.recv(1024 * 8)
print(recv)


# 407 Proxy Authentication Required
recv = s.recv(1024 * 8)

[headers_raw, body_raw] = recv.split(b"\r\n\r\n")

headers = headers_raw.split(b'\r\n')

# nonce for proxy auth
nonce = get_nonce_from_headers(headers)

# ACK 407

payload = ""
payload += f"ACK sip:{sip_srv_addr} SIP/2.0\r\n"
payload += f"Max-Forwards: 70\r\n"
payload += f"Via: SIP/2.0/UDP {sip_srv_addr}:{sip_srv_port};branch={get_branch_from_via(headers)}\r\n"
payload += f"To: <sip:{phone_number_to_call}@{sip_srv_addr}>\r\n"
payload += f"From: <sip:{sip_username}@{my_ip}>;tag={get_tag_from_from(headers)}\r\n"
payload += f"Call-ID: 2xTb9vxSit55XU7p9@{sip_srv_addr}:{sip_srv_port}\r\n"
payload += f"CSeq: 1 ACK\r\n"
payload += f"Content-Length: 0"
payload += f"\r\n\r\n"


s.sendto(
    payload.encode("utf8"),
    (sip_srv_addr, sip_srv_port)
)

# DO NOT RECEIVE NOTGHING; I'LL SEND NEW INVITE (2) WITH PROXY-AUTHORIZATION

payload = ""
payload += f"INVITE sip:{sip_srv_addr} SIP/2.0\r\n"
payload += f"Via: SIP/2.0/UDP {sip_srv_addr}:{sip_srv_port};branch=z9hG4bK721e.4\r\n"
payload += f"Max-Forwards: 70\r\n"
payload += f"Contact: <sip:{sip_username}@{sip_srv_addr};transport=udp>\r\n"
payload += f"To: <sip:{phone_number_to_call}@{sip_srv_addr}>\r\n"
payload += f"From: <sip:{sip_username}@{my_ip}>;tag=9fxced76sa\r\n"
payload += f"Call-ID: 2xTb9vxSit55XU7p9\r\n"
payload += f"CSeq: 2 INVITE\r\n"
payload += f"Content-Length: {len(body)}\r\n"
payload += f'Proxy-Authorization: Digest username="{sip_username}", realm="sip.telnyx.com", nonce="{nonce}", uri="sip:{sip_username}@sip.telnyx.com", opaque="{get_opaque_from_407(headers)}", response="{get_auth_response("INVITE", nonce, f"sip:{sip_username}@sip.telnyx.com")}", algorithm=MD5'

payload += f"\r\n\r\n"

payload += f"{body}"


s.sendto(
    payload.encode("utf8"),
    (sip_srv_addr, sip_srv_port)
)


# 100 Telnyx trying
recv = s.recv(1024 * 8)
recv = s.recv(1024 * 8)
recv = s.recv(1024 * 8)
recv = s.recv(1024 * 8)