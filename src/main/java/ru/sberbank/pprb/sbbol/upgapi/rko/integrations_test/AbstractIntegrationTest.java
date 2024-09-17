package ru.sberbank.pprb.sbbol.upgapi.rko.integrations_test;

import io.qameta.allure.Step;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeAll;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


public abstract class AbstractIntegrationTest {
    private static String URL;
    private static String USER_LOGIN;
    private static String PASSWORD;
    private static String ORG_ID;
    private String sessionId;

    private static final String REQUEST_NOT_PROCESSED = "<!--NOT PROCESSED YET-->";

    private static final String SERVER_ACCESS_ERROR = "00000000-0000-0000-0000-000000000012";

    @BeforeAll
    static void setup(){
        Properties properties = new Properties();
        try {
            properties.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("application.properties"));
        } catch (IOException e) {
            fail(e.getMessage());
        }

        URL = properties.getProperty("upg-integration-test.url");
        assertNotNull(URL, "URL is null");
        USER_LOGIN = properties.getProperty("upg-integration-test.user_login");
        assertNotNull(USER_LOGIN, "USER_LOGIN is null");
        PASSWORD = properties.getProperty("upg-integration-test.password");
        assertNotNull(PASSWORD, "PASSWORD is null");
        ORG_ID = properties.getProperty("upg-integration-test.org_id");
        assertNotNull(ORG_ID, "ORG_ID is null");
    }

    /**
     * Отправка запроса через УПШ
     *
     * @param body xml - тело запроса
     * @return возвращает тикет запроса
     */
    @Step("Отправка запроса sendRequestSRP без подписи")
    public String sendRequest(String body) {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(URL)).
                setHeader("Content-Type", "text/xml; charset=UTF-8").
                setHeader("SOAPAction", "\"\"").
                setHeader("User-Agent", "UPGTEST/1.0.0 (USSR win G7; Android 8.0.0; ru_RU; 65) RSA/2.0 kaspersky/15.0").
                POST(HttpRequest.BodyPublishers.ofString(body)).build();
        try {
            HttpResponse<String> send = client.send(request, HttpResponse.BodyHandlers.ofString());
            return send.body();
        } catch (IOException | InterruptedException e) {
            fail();
            return null;
        }
    }

    /**
     * Методы отправки запроса и получения статуса
     *
     * @param upgRequest xml запрос
     * @return получение статуса запроса
     * @throws IOException
     */
    @Step("Отправка запроса sendRequestSRP без подписи и получение статуса запроса")
    public String sendRequestAndGetStatus(String upgRequest) throws IOException {
        sendLoginAndPassword();
        String ticketId = sendRequestSRP(sessionId, upgRequest);
        return getStatus(ticketId, sessionId);
    }

    /**
     * Отправка метода на сооздание запроса УПШ с подписью
     *
     * @param upgRequest   xml запрос
     * @param tokenSession токенная сессия
     * @return Возвращает статус запроса
     * @throws IOException
     */
    @Step("Отправка запроса sendRequestSRP с подписью и получение его статуса getRequestStatusSRP")
    public String sendSignedRequestAndGetStatus(String upgRequest, String tokenSession) throws IOException {
        String ticketId = sendRequestSRP(tokenSession, upgRequest);
        return getStatus(ticketId, tokenSession);
    }

    /**
     * Метод авторизации в УПШ
     *
     * @return session_id
     */
    @Step("Авторизация в УПШ")
    public String sendLoginAndPassword() throws IOException {
        if (sessionId == null) {
            String result = sendRequest(String.format(
                    "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:upg=\"http://upg.sbns.bssys.com/\">\n" +
                            "    <soapenv:Header/>\n" +
                            "    <soapenv:Body>\n" +
                            "        <upg:preLogin>\n" +
                            "            <upg:userLogin>%s</upg:userLogin>\n" +
                            "            <upg:changePassword>false</upg:changePassword>\n" +
                            "        </upg:preLogin>\n" +
                            "    </soapenv:Body>\n" +
                            "</soapenv:Envelope>", USER_LOGIN));
            String[] extractReturns = extractReturns(result);
            String session_id = extractReturns[2];
            assertSuccess(extractReturns[3]);
            byte[] salt = Base64.getDecoder().decode(extractReturns[0]);
            byte[] vBbytes = Base64.getDecoder().decode(extractReturns[1]);
            sessionId = extractSession(session_id);
            SRPClientContext srpClientContext = new SRPClientContext(USER_LOGIN, PASSWORD);
            byte[] data = srpClientContext.makeAuthorizationData(salt, vBbytes);
            String passwordData = Base64.getEncoder().encodeToString(data);
            String extPasswordData = Base64.getEncoder().encodeToString(srpClientContext.getAbytes());

            String loginReq = String.format("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:upg=\"http://upg.sbns.bssys.com/\">\n" +
                    "    <soapenv:Header/>\n" +
                    "    <soapenv:Body>\n" +
                    "      <upg:login>\n" +
                    "         <upg:sessionId>%s</upg:sessionId>\n" +
                    "         <upg:clientAuthData>%s</upg:clientAuthData>\n" +
                    "         <upg:clientAuthData>%s</upg:clientAuthData>\n" +
                    "      </upg:login>\n" +
                    "    </soapenv:Body>\n" +
                    "</soapenv:Envelope>", sessionId, passwordData, extPasswordData);

            String sessionTicket = sendRequest(loginReq);

            String[] loginParams = extractReturns(sessionTicket);
            assertSuccess(loginParams[1]);
            sessionId = extractSession(loginParams[2]);
            return sessionId;
        }
        return sessionId;
    }

    public static String[] extractReturns(String response) {
        return StringUtils.substringsBetween(response, "<return>", "</return");
    }

    public static String extractSession(String encodedSession) throws IOException {
        return new String(Base64.getDecoder().decode(encodedSession));
    }

    /**
     * Отправка sendRequestSRP
     *
     * @param sessionId  - идентификатор сессии
     * @param upgRequest - xml запрос
     * @return возвращает идентификатор тикета запроса
     */
    @Step("Отправка запроса sendRequestSRP без подписи")
    public String sendRequestSRP(String sessionId, String upgRequest) {
        String result = sendRequest(String.format("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:upg=\"http://upg.sbns.bssys.com/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "      <upg:sendRequestsSRP>\n" +
                "         <upg:requests>\n" +
                "            <![CDATA[" +
                "%s\n" +
                "]]>\n" +
                "         </upg:requests>\n" +
                "         <upg:sessionId>%s</upg:sessionId>\n" +
                "      </upg:sendRequestsSRP>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>", upgRequest, sessionId));
        String[] responseReturns = extractReturns(result);
        return responseReturns[0];
    }

    /**
     * Отправка getRequestStatusSRP
     *
     * @param ticketId  - идентификатор тикета запроса
     * @param sessionId сессия
     * @return возвращает статус запроса
     */
    @Step("Запрос статуса getRequestStatusSRP")
    public String getStatus(String ticketId, String sessionId) {
        String[] responseReturns;
        String request = String.format("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:upg=\"http://upg.sbns.bssys.com/\">\n" +
                "    <soapenv:Header/>\n" +
                "    <soapenv:Body>\n" +
                "        <upg:getRequestStatusSRP>\n" +
                "            <upg:requests>%s</upg:requests>\n" +
                "            <upg:sessionId>%s</upg:sessionId>\n" +
                "        </upg:getRequestStatusSRP>\n" +
                "    </soapenv:Body>\n" +
                "</soapenv:Envelope>", ticketId, sessionId, ORG_ID);
        int i = 0;
        while (i++ < 5) {
            String response = sendRequest(request);
            responseReturns = extractReturns(response);
            if (responseReturns.length > 0) {
                String innerResponse = StringEscapeUtils.unescapeXml(responseReturns[0]);
                if (!innerResponse.equals(REQUEST_NOT_PROCESSED)//Если запрос обработан
                        && !innerResponse.contains(SERVER_ACCESS_ERROR)) {//Если не произошла ошибка доступа к серверу сббол
                    if (response.startsWith("<!--")) {
                        fail("Request was not handled: " + response);
                    }
                    return (innerResponse);
                }
            }
            try {
                TimeUnit.SECONDS.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        fail("Request handle timeout");
        return null;
    }

    public static void assertSuccess(String result) {
        if (!"AA==".equals(result)) {
            throw new RuntimeException("result not equals AA== :" + result);
        }
    }


}


