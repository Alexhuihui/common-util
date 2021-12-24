package top.alexmmd.util.security;

import cn.hutool.core.collection.ListUtil;
import cn.hutool.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author 汪永晖
 * @date 2021/12/24 18:43
 */
@SpringBootTest
public class JwtUtilTest {

    @Test
    public void testJwtValid() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.putOpt("uid", 1);
        jsonObject.putOpt("role", ListUtil.of("ADMIN", "USER"));
        String token = JwtUtil.generateToken(jsonObject);
        System.out.println("token = " + token);
        boolean b = JwtUtil.verifierToken(token);
        System.out.println("b = " + b);
        Assert.assertTrue(b);
    }
}
