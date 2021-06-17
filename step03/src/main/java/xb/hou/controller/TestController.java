package xb.hou.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @title: TestController
 * @Author xbhou
 * @Date: 2021-06-15 22:18
 * @Version 1.0
 */
@RestController
@RequestMapping("/test")
public class TestController {
    @GetMapping("/test")
    public String test() {
        return "SUCCESS";
    }
}
