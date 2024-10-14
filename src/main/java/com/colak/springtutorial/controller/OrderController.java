package com.colak.springtutorial.controller;

import com.colak.springtutorial.dto.OrderModel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/orders")
@Slf4j
public class OrderController {

    private int counter;

    // http://localhost:8080/orders/1
    @GetMapping("/{orderId}")
    public ResponseEntity<OrderModel> getOrderById(@PathVariable String orderId,
                                                   @RequestParam Map<String, String> allParams,
                                                   @RequestHeader Map<String, String> allHeaders) {

        // Log all request headers
        log.info("Received params: {}", allParams);
        log.info("Received headers: {}", allHeaders);

        int oldValue = counter++;

        // Throw exceptions to test Retry filter
        if (isEven(oldValue)) {
            throw new RuntimeException("Even number " + oldValue);
        } else {
            log.info("Odd number {}", oldValue);
        }
        OrderModel orderModel = new OrderModel();
        orderModel.setOrderId(orderId);
        return ResponseEntity.ok(orderModel);
    }

    private boolean isEven(int value) {
        return value % 2 == 0;
    }
}
