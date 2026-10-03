package com.enterprise.portal

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class PortalApplication

fun main(args: Array<String>) {
    runApplication<PortalApplication>(*args)
}
