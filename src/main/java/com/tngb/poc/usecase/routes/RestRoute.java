package com.tngb.poc.usecase.routes;

import com.tngb.poc.usecase.processors.RequestProcessor;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.rest.RestBindingMode;
import org.springframework.stereotype.Component;

@Component
public class RestRoute extends RouteBuilder {

    @Override
    public void configure() throws Exception {
        restConfiguration()
                .component("jetty")
                .host("0.0.0.0")
                .port(8080)
                .bindingMode(RestBindingMode.auto)
                .enableCORS(true);

        rest("/api/rest")
                .produces("application/json")
                .post("/inputdata")
                .to("direct:processInputData");

        from("direct:processInputData")
                .routeId("processInputData")
                .convertBodyTo(String.class)
                .log(LoggingLevel.INFO, "Received Hit with the Body :: ${body}")
                .setProperty("privateKeyPath",simple("{{source-a-private-key-path}}"))
                .setProperty("publicKeyPath",simple("{{source-b-public-key-path}}"))
                .setProperty("privateKeyPassword",simple("{{source-a-private-key-password}}"))
                .process(new RequestProcessor())
                .setProperty("inputFileName", simple("inputfile-signed-encypted-${date-with-timezone:now:IST:yyyyMMddHHmmss}.txt"))
                .toD("{{destination-file-path}}?fileName=${exchangeProperty.inputFileName}")
                .log(LoggingLevel.INFO, "${exchangeProperty.inputFileName} File created with PGP Encrypted Body :: ${body}")
                .setBody(simple("{\"result\":\"File created successfully!!\"}"));
    }
}
