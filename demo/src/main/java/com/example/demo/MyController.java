package com.example.demo;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController
public class MyController {


  @RequestMapping("/")
  String home() {
	  System.out.println("....called controller....");
      return "{\"name\":\"Hello, World\"}";
  }
	
}
