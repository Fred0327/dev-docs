#!/usr/bin/env python
# encoding: utf-8

import requests
import time
import urllib
import hashlib
import hmac
import zklink_sdk as sdk

domain_url = "http://domain_url"
eth_priv_key = ""
api_key = "your api key"
api_secret = "your api secret"


def server_info():
    path = "/mm/api/server"
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url)
    print(resp.json())
    return resp.json()


def products_info():
    path = "/mm/api/products"
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url)
    print(resp.json())
    return resp.json()


def get_jwt_token():
    args = {
        "timestamp": int(time.time())
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/users?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url, headers=headers)
    print(resp.text)
    return resp.text


def get_self_info():
    args = {
        "timestamp": int(time.time())
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/self?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url, headers=headers)
    print(resp.json())
    return resp.json()


def get_slot_batchly(cnt):
    args = {
        "timestamp": int(time.time()),
        "count": cnt,
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/slot?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url, headers=headers)
    print(resp.json())
    return resp.json()


def place_order(acct_id, product, side, time_in_force, price, size,
                taker_fee_ratio, maker_fee_ratio, slot, nonce, client_oid=""):
    assert side in ("BUY", "SELL")
    assert time_in_force in ("GTC", "IOC", "FOK", "GTX")

    zksigner = sdk.ZkLinkSigner.new_from_hex_eth_signer(eth_priv_key)

    order = sdk.Order(
        account_id=acct_id,
        sub_account_id=1,
        slot_id=slot,
        nonce=nonce,
        base_token_id=product.get('l2baseCurrencyId'),
        quote_token_id=product.get('l2quoteCurrencyId'),
        amount=str(int(price * (10 ** 18))),
        price=str(int(size * (10 ** 18))),
        is_sell=side == "BUY",
        has_subsidy=False,
        maker_fee_rate=maker_fee_ratio,
        taker_fee_rate=taker_fee_ratio,
        signature=None,
    )
    signed_order = order.create_signed_order(zksigner)
    order_signature = signed_order.get_signature();

    args = {
        "timestamp": int(time.time()),
        "symbol": product.get('id'),
        "side": side,
        "type": "LIMIT",
        "timeInForce": time_in_force,
        "price": int(price * (10 ** 18)),
        "quantity": int(size * (10 ** 18)),
        "takerFeeRatio": taker_fee_ratio,
        "makerFeeRatio": maker_fee_ratio,
        "slot": slot,
        "nonce": nonce,
        "userPubkey": order_signature.pub_key,
        "orderSignature": order_signature.signature,
    }
    if len(client_oid) > 0:
        args["clientOid"] = client_oid

    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/orders?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.post(url, headers=headers)
    print(resp.json())
    return resp.json()


def cancel_order(product_id, order_id):
    args = {
        "timestamp": int(time.time()),
        "symbol": product_id,
        "orderId": order_id,
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/order?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.delete(url, headers=headers)
    print(resp.json())
    return resp.json()


def cancel_orders(product_id):
    args = {
        "timestamp": int(time.time()),
        "symbol": product_id,
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/orders?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.delete(url, headers=headers)
    print(resp.json())
    return resp.json()


def list_orders(product_id, start_time, end_time, limit):
    args = {
        "timestamp": int(time.time()),
        "symbol": product_id,
        "startTime": start_time,
        "endTime": end_time,
        "limit": limit,
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/orders?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url, headers=headers)
    print(resp.json())
    return resp.json()


def get_order(product_id, order_id):
    args = {
        "timestamp": int(time.time()),
        "symbol": product_id,
        "orderId": order_id,
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/order?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url, headers=headers)
    print(resp.json())
    return resp.json()


def list_open_orders(product_id, limit):
    args = {
        "timestamp": int(time.time()),
        "symbol": product_id,
        "limit": limit,
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/openOrders?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url, headers=headers)
    print(resp.json())
    return resp.json()


def accounts_info():
    args = {
        "timestamp": int(time.time())
    }
    headers = {
        "X-MBX-APIKEY": api_key
    }

    args_str = urllib.parse.urlencode(args)
    signature = hmac.new(bytes.fromhex(api_secret),
                         msg=args_str.encode("ascii"),
                         digestmod=hashlib.sha256) \
        .hexdigest().lower()
    path = "/mm/api/accounts?%s&signature=%s" % (args_str, signature)
    url = "%s%s" % (domain_url, path)
    resp = requests.get(url, headers=headers)
    print(resp.json())
    return resp.json()


def get_product_by_id(product_id):
    for p in products_info():
        if p.get('id') == product_id:
            return p
    return None


if __name__ == "__main__":
    server_info()
    products_info()
    eth_usd_product = get_product_by_id('wETH-USD')
    get_jwt_token()
    self_info = get_self_info()
    slots = get_slot_batchly(5)
    order = place_order(self_info.get('l2userId'), eth_usd_product, "BUY", "GTC", 300.0, 1.0, 10, 5, slots[0]["slot"],
                        slots[0]["nonce"])
    print(order.get('id'))
    cancel_order("wETH-USD", order.get('id'))
    list_orders("wETH-USD", 0, int(time.time()), 10)
    get_order("wETH-USD", order.get('id'))
    list_open_orders("wETH-USD", 10)
    accounts_info()
