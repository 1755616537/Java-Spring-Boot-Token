package com.dabaoyutech.lingshou.util;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class TokenPrivateUtils {
    private final Base64.Decoder decoder = Base64.getDecoder();
    private final Base64.Encoder encoder = Base64.getEncoder();

    //    例子
    private void LZ() {
        TokenPrivateUtils TokenPrivateUtils = new TokenPrivateUtils();
//        生成Token
        JSONObject payloadObject = new JSONObject();
        payloadObject.put("username", "2");
        payloadObject.put("code", "2");
        payloadObject.put("time", String.valueOf(System.currentTimeMillis()));
        String Token = TokenPrivateUtils.SetToken(payloadObject);
        System.out.println("GetShangPinImg,Token1生成：" + Token);
//        验证Token
        JSONObject TokenGetReturn = TokenPrivateUtils.GetToken(Token);
        if (!TokenGetReturn.getString("errcode").equals("0")) {
            System.out.println("GetShangPinImg,Token3错误：" + TokenGetReturn.getString("msg"));
        } else {
            System.out.println("GetShangPinImg,Token2成功,返回String型json格式payload中间信息：" + TokenGetReturn.getString("msg"));
        }
    }

    //    获取Token 需提供中间部分信息(payload)JSONObject类型
    public String SetToken(JSONObject payloadObject) {
        JSONObject headerObject = new JSONObject();
        headerObject.put("typ", "JWT");
        headerObject.put("alg", "HS256");
        String header = JSONObject.toJSONString(headerObject);
        String payload = JSONObject.toJSONString(payloadObject);
        String signature = HMACSHA256(header + payload);
        return setbase64(header) + '.' + setbase64(payload) + '.' + setbase64(signature);
    }

    //    获取Token 在原有的基础上添加Session记录
    public String SetTokenSession(JSONObject payloadObject, HttpSession session) {
        session.setAttribute("TokenPrivate", "1");
        return SetToken(payloadObject);
    }

    //    检验token 成功返回 公共部分信息 json字符串类型
    public JSONObject GetToken(String Token) {
        JSONObject Return = new JSONObject();
        if (StringUtils.isBlank(Token)) {
            Return.put("errcode", "1");
            Return.put("msg", "token为空");
            return Return;
        }
        String[] TokenArr = Token.split("\\.");
        if (TokenArr.length != 3) {
            Return.put("errcode", "1");
            Return.put("msg", "token格式错误");
            return Return;
        }
        String header = getbase64(TokenArr[0]);
        String payload = getbase64(TokenArr[1]);
        String signature = HMACSHA256(header + payload);
        String setToken = setbase64(header) + '.' + setbase64(payload) + '.' + setbase64(signature);
        if (!Token.equals(setToken)) {
            Return.put("errcode", "1");
            Return.put("msg", "token校验失败");
            return Return;
        }
        Return.put("errcode", "0");
        Return.put("msg", payload);
        return Return;
    }

    //    检验Token 在原有的基础上检验Session记录
    public JSONObject GetTokenSession(String Token, HttpSession session) {
        JSONObject Return = new JSONObject();
        String SessionTokenPrivate = ObjectUtils.toString(session.getAttribute("TokenPrivate"), "");
        if (StringUtils.isBlank(SessionTokenPrivate)) {
            Return.put("errcode", "1");
            Return.put("msg", "token已过期或不存在");
            return Return;
        }
        return GetToken(Token);
    }

    private String setbase64(String text) {
        byte[] textByte = text.getBytes(StandardCharsets.UTF_8);
        return encoder.encodeToString(textByte);
    }

    private String getbase64(String text) {
        String a="";
        try {
            a=new String(decoder.decode(text), StandardCharsets.UTF_8);
        }catch (Exception e){
//            e.printStackTrace();
        }
        return a;
    }

    private static String HMACSHA256(String data) {
        Mac sha256_HMAC = null;
        try {
            sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec("ZCfasfhuaUUHufguGuwu2020BQWE".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256_HMAC.init(secret_key);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        assert sha256_HMAC != null;
        byte[] array = sha256_HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte item : array) {
            sb.append(Integer.toHexString((item & 0xFF) | 0x100).substring(1, 3));
        }
        return sb.toString().toUpperCase();
    }
}
