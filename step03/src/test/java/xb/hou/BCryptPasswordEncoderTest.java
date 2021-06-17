package xb.hou;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @title: BCryptPasswordEncoderTest
 * @Author xbhou
 * @Date: 2021-06-17 13:08
 * @Version 1.0
 */
public class BCryptPasswordEncoderTest {
    @Test
    public void test01() {
        // 创建密码解析器
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        // 对密码进行加密
        String xbhou = encoder.encode("xbhou");
        System.out.println("加密后的数据：" + xbhou);
        System.out.println("判断原字符串和加密之前是否匹配：" + encoder.matches("xbhou", xbhou));
    }
}
