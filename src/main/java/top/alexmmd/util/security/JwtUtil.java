package top.alexmmd.util.security;

import cn.hutool.core.collection.ListUtil;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.extern.slf4j.Slf4j;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author 汪永晖
 * @date 2021/12/24 15:52
 */
@Slf4j
public class JwtUtil {

    private static final RSAPrivateKey PRIVATE_KEY;
    private static final RSAPublicKey PUBLIC_KEY;

    static {
        PRIVATE_KEY = (RSAPrivateKey) PemUtil.readPrivateKeyFromFile("C:\\data\\java_private.key", "RSA");
        PUBLIC_KEY = (RSAPublicKey) PemUtil.readPublicKeyFromFile("C:\\data\\pub.key", "RSA");
    }

    public static String generateToken(JSONObject jsonObject) {
        try {
            //加密时，使用私钥生成RSA算法对象
            Algorithm algorithm = Algorithm.RSA256(null, PRIVATE_KEY);
            DateTime date = DateUtil.date();
            return JWT.create()
                    //签发人
                    .withIssuer("auth-server")
                    //接收者
                    .withAudience("client")
                    //签发时间
                    .withIssuedAt(date)
                    //过期时间
                    .withExpiresAt(DateUtil.offsetMinute(date, 5))
                    //相关信息
                    .withClaim("data", jsonObject.toString())
                    //签入
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
            log.error(exception.getMessage());
        }
        return null;
    }

    public static boolean verifierToken(String token) {
        // 根据密钥对生成RS256算法对象
        Algorithm algorithm = Algorithm.RSA256(PUBLIC_KEY, null);
        JWTVerifier verifier = JWT.require(algorithm)
                .build();

        try {
            // 验证Token，verifier自动验证
            DecodedJWT jwt = verifier.verify(token);
            // 打印用户声明的信息
            Claim data = jwt.getClaim("data");
            JSONObject jsonObject = JSONUtil.parseObj(data.asString());
            for (String key : jsonObject.keySet()) {
                log.info("key === {}, value === {}", key, jsonObject.get(key));
            }
            return true;
        } catch (JWTVerificationException e) {
            log.error("Token无法通过验证! " + e.getMessage());
            return false;
        }
    }

    public static void main(String[] args) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.putOpt("uid", 1);
        jsonObject.putOpt("role", ListUtil.of("ADMIN", "USER"));
        String token = JwtUtil.generateToken(jsonObject);
        System.out.println("token = " + token);
        boolean b = JwtUtil.verifierToken(token);
        System.out.println("b = " + b);
    }
}
