package jwtLogin.jwt_login.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class AdminController {

    // 어드민 페이지
    @GetMapping("/admin")
    public String adminP() {
        return "Admin Controller";
    }
}
