# app.py
from flask import Flask, render_template, request, redirect, url_for
from rsa_cipher import generate_rsa_keypair, encrypt_rsa, decrypt_rsa
from elgamal_cipher import generate_elgamal_keypair, encrypt_elgamal, decrypt_elgamal
from ecc_cipher import generate_ecc_keypair, encrypt_ecc, decrypt_ecc, curve_params, Point, encode_point_from_text, decode_point_to_text, ecies_encrypt, ecies_decrypt

app = Flask(__name__)

# 全局保存当前密钥对
KEYS = {
    'RSA': {'pub': None, 'priv': None},
    'ElGamal': {'pub': None, 'priv': None},
    'ECC': {'pub': None, 'priv': None}
}


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    # 设置默认算法为 RSA（用于首次加载页面）
    current_algo = request.form.get('algorithm', 'RSA')

    if request.method == 'POST':
        algo = current_algo
        action = request.form.get('action')
        data = request.form.get('data', '')

        # 生成密钥
        if action == 'genkey':
            if algo == 'RSA':
                pub, priv = generate_rsa_keypair(1024)
            elif algo == 'ElGamal':
                pub, priv = generate_elgamal_keypair(1024)
            else:
                priv, pub = generate_ecc_keypair(curve_params)
            KEYS[algo]['pub'] = pub
            KEYS[algo]['priv'] = priv

        # 加密
        elif action == 'encrypt':
            pub = KEYS[algo]['pub']
            if pub is None:
                result = "请先生成密钥！"
            else:
                try:
                    if algo == 'RSA':
                        ct = encrypt_rsa(data.encode(), pub)
                        result = f"密文：{ct}"
                    elif algo == 'ElGamal':
                        try:
                            # 将明文转换为整数
                            data_bytes = data.encode('utf-8')
                            m = int.from_bytes(data_bytes, 'big')

                            # 检查明文长度
                            p = pub[0]  # 获取素数p
                            if m >= p:
                                result = f"错误：明文太长，最大允许长度为 {p.bit_length() // 8 - 1} 字节"
                            else:
                                ct = encrypt_elgamal(m, pub, hmac_key=b'secret')
                                result = f"密文：{ct}"
                        except Exception as e:
                            result = f"加密错误：{str(e)}"
                    else:
                        # ECC-ECIES加密
                        try:
                            ct = ecies_encrypt(data.encode('utf-8'), pub, curve_params)
                            result = f"密文：{ct}"
                        except Exception as e:
                            result = f"加密错误：{str(e)}"
                except Exception as e:
                    result = f"加密错误：{str(e)}"

        # 解密
        elif action == 'decrypt':
            priv = KEYS[algo]['priv']
            pub = KEYS[algo]['pub']
            if priv is None:
                result = "请先生成密钥！"
            else:
                try:
                    if algo == 'RSA':
                        ct_int = int(data)
                        pt = decrypt_rsa(ct_int, priv).decode()
                        result = f"明文：{pt}"
                    elif algo == 'ElGamal':
                        try:
                            # 解析密文元组
                            ct = eval(data)
                            if not isinstance(ct, tuple) or len(ct) != 3:
                                raise ValueError("无效的密文格式")

                            # 解密
                            m = decrypt_elgamal(ct, priv, hmac_key=b'secret', public_key=pub)

                            # 将整数转换回字节，然后解码为字符串
                            pt = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
                            result = f"明文：{pt}"
                        except Exception as e:
                            result = f"解密错误：{str(e)}"
                    else:
                        # ECC-ECIES解密
                        try:
                            ct = eval(data)
                            pt = ecies_decrypt(ct, priv, curve_params).decode('utf-8')
                            result = f"明文：{pt}"
                        except Exception as e:
                            result = f"解密错误：{str(e)}"
                except Exception as e:
                    result = f"解密错误：{str(e)}"

    return render_template('index.html',
                           keys=KEYS,
                           result=result,
                           current_algo=current_algo)  # 传递当前算法到模板


if __name__ == '__main__':
    # 生产/测试环境请关闭 debug
    app.run(debug=False)