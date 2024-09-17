package ru.sberbank.pprb.sbbol.upgapi.rko.integrations_test;


import io.qameta.allure.Allure;
import io.qameta.allure.Description;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.*;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

@EnableAutoConfiguration
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PayDocRuIntegrationTest extends AbstractIntegrationTest {

    private static final String PAYDOCRU_FILE_PATH = "src/test/resources/upgrequests/PayDocRuBase.xml";
    private static final String SIGNED_PAYDOCRU_FILE_PATH = "src/test/resources/upgrequests/PayDocRuSigned.xml";
    private static final String SIGNED_PAYDOCRU_DIGEST_PATH = "src/test/resources/upgrequests/PayDocRuDigest";
    private static final String HOLDING_PAYDOCRU_FILE_PATH = "src/test/resources/upgrequests/PayDocRuHolding.xml";
    private static final String HOLDING_PAYDOCRU_DIGEST_PATH = "src/test/resources/upgrequests/PayDocRuHoldingDigest";
    private static final String DOCIDS_FILE_PATH = "src/test/resources/upgrequests/DocId.xml";
    private static final String DELIVERED = "DELIVERED";
    private static final String CREATED = "CREATED";
    private static final String FAIL = "FAIL";
    private static final Set STATUSES = Set.of(DELIVERED, "ACCEPTED", "CREATED", "CHECKERROR", "ACCEPTED_BY_ABS");
    private static final String INVALIDEDS = "INVALIDEDS";
    private TokenService tokenService = new TokenService();
    public static final String DOCEXTID = UUID.randomUUID().toString();

    @Test
    @Order(1)
    @DisplayName("Создание РПП с подписью в УПШ")
    @Description("1.Получение токенной сессии\n2.Формирование дайджеста запроса\n3.Подписание запроса\n4.Отправка запроса на создание РПП\n5.Получение запроса статуса РПП")
    public void createPayDocRuSigned() throws IOException {
        String tokenSession = tokenService.loginAndGetSession();
        String requestId = UUID.randomUUID().toString();
        String accDocNo = RandomStringUtils.randomNumeric(5, 6);
        String docExtId = DOCEXTID;
        String docDate = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

        Path path = Paths.get(SIGNED_PAYDOCRU_DIGEST_PATH);
        String digest = String.format(Files.readString(path.toAbsolutePath()), docExtId, accDocNo, docDate);
        String signValue = tokenService.createDigestAndSignValue(digest);
        Allure.attachment("Клиентский дайджест:", digest);

        path = Paths.get(SIGNED_PAYDOCRU_FILE_PATH);
        String request = String.format(Files.readString(path.toAbsolutePath()), requestId, docExtId, accDocNo, docDate, signValue);
        Allure.attachment("Запрос sendRequestSRP PayDocRu:", request);

        String result = sendSignedRequestAndGetStatus(request, tokenSession);
        Allure.attachment("Ответ на getRequestStatusSRP PayDocRu:", result);
        Assertions.assertFalse(result.contains("Неспецифицированная ошибка"), "Пришла неспецифицированная ошибка");
        String resultStatus = StringUtils.substringBetween(result, "statusStateCode=\"", "\"");
        Assertions.assertTrue(result.contains(DELIVERED), "Статус запроса на создание РПП: " + resultStatus);

        path = Paths.get(DOCIDS_FILE_PATH);
        String requestDocID = String.format(Files.readString(path.toAbsolutePath()), UUID.randomUUID(), docExtId);
        Allure.attachment("Запрос sendRequestSRP DocIds:", requestDocID);

        String resultDocId = sendRequestAndGetStatus(requestDocID);
        String resultStatusDocId = StringUtils.substringBetween(resultDocId, "statusStateCode=\"", "\"");
        Assertions.assertTrue(STATUSES.contains(resultStatusDocId), "Статус документа: " + resultStatusDocId);
        Allure.attachment("Ответ getRequestStatusSRP DocIds:", resultStatusDocId);
    }

    @Test
    @DisplayName("Создание РПП в УПШ без подписи")
    @Description("1.Получение токенной сессии\n2.Формирование дайджеста запроса\n3.Подписание запроса\n4.Отправка запроса на создание РПП\n5.Получение запроса статуса РПП")    public void createPayDocRu() throws IOException {
        String requestId = UUID.randomUUID().toString();
        String accDocNo = RandomStringUtils.randomNumeric(5, 6);
        String docExtId = UUID.randomUUID().toString();
        String docDate = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
        Path path = Paths.get(PAYDOCRU_FILE_PATH);
        String request = String.format(Files.readString(path.toAbsolutePath()), requestId, docExtId, accDocNo, docDate);
        Allure.attachment("Запрос sendRequestSRP PayDocRu:", request);

        String result = sendRequestAndGetStatus(request);
        Allure.attachment("Ответ на getRequestStatusSRP PayDocRu:", result);
        String resultStatus = StringUtils.substringBetween(result, "statusStateCode=\"", "\"");
        Assertions.assertTrue(result.contains(DELIVERED), "Статус запроса на создание РПП: " + resultStatus);

        path = Paths.get(DOCIDS_FILE_PATH);
        String requestDocID = String.format(Files.readString(path.toAbsolutePath()), "28055263-13b4-43a9-8fda-47976d1de172", docExtId);
        Allure.attachment("Запрос sendRequestSRP DocIds:", requestDocID);

        String resultDocId = sendRequestAndGetStatus(requestDocID);
        String resultStatusDocId = StringUtils.substringBetween(resultDocId, "statusStateCode=\"", "\"");
        Assertions.assertTrue(resultDocId.contains(CREATED), "Статус документа: " + resultStatusDocId);
        Allure.attachment("Ответ getRequestStatusSRP DocIds:", resultStatusDocId);
    }

    //TODO разблокировать тест после создания второго пользователя на втором пине эмулятора токена
    @Disabled
    @Test
    @DisplayName("Создание РПП ГО по ДЗО в УПШ")
    public void createPayDocRuHolding() throws IOException {
        String tokenSession = tokenService.loginAndGetSession();
        String requestId = UUID.randomUUID().toString();
        String accDocNo = RandomStringUtils.randomNumeric(5, 6);
        String docExtId = UUID.randomUUID().toString();
        String docDate = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

        Path path = Paths.get(HOLDING_PAYDOCRU_DIGEST_PATH);
        String digest = String.format(Files.readString(path.toAbsolutePath()), docExtId, accDocNo, docDate);
        String signValue = tokenService.createDigestAndSignValue(digest);

        path = Paths.get(HOLDING_PAYDOCRU_FILE_PATH);
        String request = String.format(Files.readString(path.toAbsolutePath()), requestId, docExtId, accDocNo, docDate, signValue);

        String result = sendSignedRequestAndGetStatus(request, tokenSession);
        Assertions.assertFalse(result.contains("Неспецифицированная ошибка"), "Пришла неспецифицированная ошибка");
        String resultStatus = StringUtils.substringBetween(result, "statusStateCode=\"", "\"");
        Assertions.assertTrue(result.contains(DELIVERED), "Статус запроса на создание РПП: " + resultStatus);

        path = Paths.get(DOCIDS_FILE_PATH);
        String requestDocID = String.format(Files.readString(path.toAbsolutePath()), UUID.randomUUID(), docExtId);

        String resultDocId = sendRequestAndGetStatus(requestDocID);
        String resultStatusDocId = StringUtils.substringBetween(resultDocId, "statusStateCode=\"", "\"");
        Assertions.assertTrue(STATUSES.contains(resultStatusDocId), "Статус документа: " + resultStatusDocId);
    }

    @Test
    @DisplayName("Создание РПП с невалидной подписью в УПШ")
    @Description("1.Получение токенной сессии\n2.Формирование дайджеста запроса\n3.Подписание запроса\n4.Отправка запроса на создание РПП\n5.Получение запроса статуса РПП")
    public void createPayDocRuInvalidSigned() throws IOException {
        String tokenSession = tokenService.loginAndGetSession();
//        String requestId = UUID.randomUUID().toString();
        String requestId = "83c0f1ef-1b44-4cff-9c9c-b52803c92212";
        String accDocNo = RandomStringUtils.randomNumeric(5, 6);
        String docExtId = UUID.randomUUID().toString();
        String docDate = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

        Path path = Paths.get(SIGNED_PAYDOCRU_DIGEST_PATH);
        String digest = String.format(Files.readString(path.toAbsolutePath()), docExtId, "0", docDate);
        String signValue = tokenService.createDigestAndSignValue(digest);
        Allure.attachment("Клиентский дайджест:", digest);

        path = Paths.get(SIGNED_PAYDOCRU_FILE_PATH);
        String request = String.format(Files.readString(path.toAbsolutePath()), requestId, docExtId, accDocNo, docDate, signValue);
        Allure.attachment("Запрос sendRequestSRP PayDocRu:", request);

        String result = sendSignedRequestAndGetStatus(request, tokenSession);
        Allure.attachment("Ответ на getRequestStatusSRP PayDocRu:", result);
        Assertions.assertFalse(result.contains("Неспецифицированная ошибка"), "Пришла неспецифицированная ошибка");
        String resultStatus = StringUtils.substringBetween(result, "statusStateCode=\"", "\"");
        Assertions.assertTrue(result.contains(DELIVERED), "Статус запроса на создание РПП: " + resultStatus);

        path = Paths.get(DOCIDS_FILE_PATH);
        String requestDocID = String.format(Files.readString(path.toAbsolutePath()), "83c0f1ef-1b44-4cff-9c9c-b52803c92212", docExtId);
        Allure.attachment("Запрос sendRequestSRP DocIds:", requestDocID);

        String resultDocId = sendRequestAndGetStatus(requestDocID);
        String resultStatusDocId = StringUtils.substringBetween(resultDocId, "statusStateCode=\"", "\"");
        Assertions.assertTrue(resultDocId.contains(INVALIDEDS), "Статус документа: " + resultStatusDocId);
        Allure.attachment("Ответ getRequestStatusSRP DocIds:", resultStatusDocId);
    }

    @Test
    @Order(2)
    @DisplayName("Создание дубликата РПП в УПШ")
    @Description("1.Получение токенной сессии\n2.Формирование дайджеста запроса\n3.Подписание запроса\n4.Отправка запроса на создание РПП\n5.Получение запроса статуса РПП")
    public void createPayDocRuDublicat() throws IOException {
        String tokenSession = tokenService.loginAndGetSession();
        String requestId = UUID.randomUUID().toString();
        String accDocNo = RandomStringUtils.randomNumeric(5, 6);
        String docExtId = "bf968d7e-d442-4ff9-9474-d4e4b06da77a";
        String docDate = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

        Path path = Paths.get(SIGNED_PAYDOCRU_DIGEST_PATH);
        String digest = String.format(Files.readString(path.toAbsolutePath()), docExtId, "0", docDate);
        String signValue = tokenService.createDigestAndSignValue(digest);
        Allure.attachment("Клиентский дайджест:", digest);

        path = Paths.get(SIGNED_PAYDOCRU_FILE_PATH);
        String request = String.format(Files.readString(path.toAbsolutePath()), requestId, docExtId, accDocNo, docDate, signValue);
        Allure.attachment("Запрос sendRequestSRP PayDocRu:", request);

        String result = sendSignedRequestAndGetStatus(request, tokenSession);
        Allure.attachment("Ответ на getRequestStatusSRP PayDocRu:", result);
        Assertions.assertFalse(result.contains("Неспецифицированная ошибка"), "Пришла неспецифицированная ошибка");
        String resultStatus = StringUtils.substringBetween(result, "statusStateCode=\"", "\"");
        String resultMessage = StringUtils.substringBetween(result, "<Message>", "</Message>");
        Assertions.assertTrue(result.contains(FAIL), "Статус запроса на создание РПП: " + resultStatus + resultMessage);
    }
}
