package ru.sberbank.pprb.sbbol.upgapi.rko.integrations_test;

import io.qameta.allure.Step;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.TestPropertySource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Сервис токенной авторизации в УПШ
 */
@TestPropertySource("classpath:application.properties")
@Configuration
public class TokenService {
    //todo переделать под проперти
    @Value("${token-emu.host}")
    private String HOST = "http://localhost";
    @Value("${tokenEmu.port}")
    private String PORT = "8323";
    @Value("${upg-gate-url}")
    private String SBNS_UPG_ENDPOINT = "http://localhost:8323/sbns-upg/upg";

    private final String TOKEN_METHOD = "/vpnkeylocal/";
    private final static String TLS_LOGIN_BODY = "id=LOGIN&user=1&pin=111111";
    private final static String GET_BS_BODY = "id=GET_BS_LIST";
    private final static String SET_BS_BODY = "id=SET_BS_USE&bsid=2";
    private final static String GET_OBJ_LIST_BODY = "id=GET_OBJ_LIST_ID&obj_type=0";
    private final static String INIT_SIGN_BODY = "id=INIT_SIGN_H_ID&blocknum=1&obj_id=%s&datasize=45&hascert=-1&hasdata=0&mode=1";
    private final static String SET_SIGN_DATA_BODY = "id=SET_SIGN_DATA_H_ID&blocknum=1&data=%s&ctx_handle=%s";
    private final static String CALC_SIGN_BODY = "id=CALC_SIGN_H_ID&ctx_handle=%s";
    private final static String GET_SIGN_CMS_BODY = "id=GET_SIGN_CMS_H_ID&ctx_handle=%s";
    private final static String INIT_SIGN_PAYDOC_BODY = "id=INIT_SIGN_H_ID&obj_id=%s&datasize=%s&hascert=-1&hasdata=0&mode=1";
    private final static String SET_SIGN_DATA_PAYDOC_BODY = "id=SET_SIGN_DATA_H_ID&blocknum=1&data=%s&ctx_handle=%s";
    private final static String CALC_SIGN_PAYDOC_BODY = "id=CALC_SIGN_H_ID&obj_id=%s&ctx_handle=%s";


    private TokenEmulatorService service = new TokenEmulatorService();

    /**
     * Логирование через токен и получение токенной сесии
     *
     * @return токенная сессия
     * @throws IOException
     */
    public String loginAndGetSession() throws IOException {
        String response = null;
        //Авторизация на токене, получаем sid2
        response = service.sendRequestToTls(TLS_LOGIN_BODY, getUrl(""));
        String sid2 = StringUtils.substringBetween(response, "sid2=\"", "\"");
        Assertions.assertNotNull(sid2, "Не вернулся sid2");

        //Получение списка БС
        service.sendRequestToTls(GET_BS_BODY, getUrl(sid2));

        //Выбор БС
        service.sendRequestToTls(SET_BS_BODY, getUrl(sid2));

        //ПреЛогин, получение сессии и соли
        String preLoginBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:upg=\"http://upg.sbns.bssys.com/\">\n" +
                "\t<soapenv:Header/>\n" +
                "\t<soapenv:Body>\n" +
                "\t\t<upg:preLoginSign>\n" +
                "\t\t\t<upg:serial>7B71393BAF1376B396FB</upg:serial>\n" +
                "\t\t\t<upg:issue>CN=ПАО Сбербанк УЦ (ТЕСТ Q)</upg:issue>\n" +
                "\t\t</upg:preLoginSign>\n" +
                "\t</soapenv:Body>\n" +
                "</soapenv:Envelope>";
        response = service.sendRequestToTls(preLoginBody, SBNS_UPG_ENDPOINT);
        var returns = StringUtils.substringsBetween(response, "<return>", "</return");
        var sald = returns[1];
        Assertions.assertNotNull(sald, "sald is null");
        var sessionId = new String(Base64.getDecoder().decode(returns[2]));
        Assertions.assertNotNull(sessionId, "sessionId is null");

        //TLS Get Certificate
        response = service.sendRequestToTls(GET_OBJ_LIST_BODY, getUrl(sid2));
        String data = StringUtils.substringBetween(response, "data=\"", ";");
        Assertions.assertNotNull(data, "Не вернулся data");

        //Sign Init
        response = service.sendRequestToTls(String.format(INIT_SIGN_BODY, data), getUrl(sid2));
        String ctxHandle = StringUtils.substringBetween(response, "ctx_handle=\"", "\"");
        Assertions.assertNotNull(ctxHandle, "Не вернулся ctxHandle");

        //Data for Sign
        service.sendRequestToTls(String.format(SET_SIGN_DATA_BODY, sald, ctxHandle), getUrl(sid2));

        //Sign Calc
        response = service.sendRequestToTls(String.format(CALC_SIGN_BODY, ctxHandle), getUrl(sid2));
        String retcode = StringUtils.substringBetween(response, "retcode=\"", "\"");
        Assertions.assertEquals(retcode, "1", "retcode!=1");

        //Get Sign
        response = service.sendRequestToTls(String.format(GET_SIGN_CMS_BODY, ctxHandle), getUrl(sid2));
        String head = StringUtils.substringBetween(response, "head=\"", "\"");
        String suffix = StringUtils.substringBetween(response, "suffix=\"", "\"");
        Assertions.assertNotNull(head, "Не вернулся head");
        Assertions.assertNotNull(suffix, "Не вернулся suffix");

        String signValue;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] decodeHead = Base64.getDecoder().decode(head);
            out.write(decodeHead);
            byte[] decodeSuffix = Base64.getDecoder().decode(suffix);
            out.write(decodeSuffix);
            signValue = Base64.getEncoder().encodeToString(out.toByteArray());
        }

        //Логин, получение сессии
        String loginBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:upg=\"http://upg.sbns.bssys.com/\">\n" +
                "   <soapenv:Header/>\n" +
                "   <soapenv:Body>\n" +
                "      <upg:loginSign>\n" +
                "             <upg:sessionId>%s</upg:sessionId>\n" +
                "             <upg:clientAuthData>%s</upg:clientAuthData>\n" +
                "\n" +
                "      </upg:loginSign>\n" +
                "   </soapenv:Body>\n" +
                "</soapenv:Envelope>";
        response = service.sendRequestToTls(String.format(loginBody, sessionId, signValue), SBNS_UPG_ENDPOINT);
        returns = StringUtils.substringsBetween(response, "<return>", "</return");
        String code = returns[1];
        Assertions.assertEquals(code, "AA==", "Ожидался код AA==, пришел" + code);
        sessionId = new String(Base64.getDecoder().decode(returns[2]));

        return sessionId;
    }

    private String getUrl(String url) {
        return HOST + ":" + PORT + TOKEN_METHOD + url;
    }

    /**
     * Создание дайджеста и получение подписи
     *
     * @param digest незакодированный дайджест
     * @return подпись
     * @throws IOException
     */
    public String createDigestAndSignValue(String digest) throws IOException {
        var encodeDigest = Base64.getEncoder().encodeToString(digest.getBytes(StandardCharsets.UTF_8));

        String response = null;
        //Авторизация на токене, получаем sid2
        response = service.sendRequestToTls(TLS_LOGIN_BODY, getUrl(""));
        String sid2 = StringUtils.substringBetween(response, "sid2=\"", "\"");
        Assertions.assertNotNull(sid2, "Не вернулся sid2");

        //TLS Get Certificate
        response = service.sendRequestToTls(GET_OBJ_LIST_BODY, getUrl(sid2));
        String data = StringUtils.substringBetween(response, "data=\"", ";");
        Assertions.assertNotNull(data, "Не вернулся data");

        //Sign Init
        response = service.sendRequestToTls(String.format(INIT_SIGN_PAYDOC_BODY, data, data.getBytes(StandardCharsets.UTF_8).length), getUrl(sid2));
        String ctxHandle = StringUtils.substringBetween(response, "ctx_handle=\"", "\"");
        Assertions.assertNotNull(ctxHandle, "Не вернулся ctxHandle");

        //Data for Sign
        service.sendRequestToTls(String.format(SET_SIGN_DATA_PAYDOC_BODY, encodeDigest, ctxHandle), getUrl(sid2));

        //Sign Calc
        response = service.sendRequestToTls(String.format(CALC_SIGN_PAYDOC_BODY, data, ctxHandle), getUrl(sid2));
        String retcode = StringUtils.substringBetween(response, "retcode=\"", "\"");
        Assertions.assertEquals(retcode, "1", "retcode!=1");

        //Get Sign
        response = service.sendRequestToTls(String.format(GET_SIGN_CMS_BODY, ctxHandle), getUrl(sid2));
        String head = StringUtils.substringBetween(response, "head=\"", "\"");
        String suffix = StringUtils.substringBetween(response, "suffix=\"", "\"");
        Assertions.assertNotNull(head, "Не вернулся head");
        Assertions.assertNotNull(suffix, "Не вернулся suffix");

        String signValue;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] decodeHead = Base64.getDecoder().decode(head);
            out.write(decodeHead);
            byte[] decodeSuffix = Base64.getDecoder().decode(suffix);
            out.write(decodeSuffix);
            signValue = Base64.getEncoder().encodeToString(out.toByteArray());
        }

        return signValue;

    }
}
