package xb.hou.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @title: UserController
 * @Author xbhou
 * @Date: 2021-06-24 15:51
 * @Version 1.0
 */
@RequestMapping("/user")
@RestController
public class UserController {
    @GetMapping("/get")
    @PreAuthorize("hasAnyAuthority('user:edit')")
    public String getInfo() {
        return "admin";
    }

    @GetMapping("/logout")
    public String logout() {
        return "SUCCESS";
    }
}
