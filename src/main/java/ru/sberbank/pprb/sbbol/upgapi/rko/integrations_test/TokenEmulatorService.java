package ru.sberbank.pprb.sbbol.upgapi.rko.integrations_test;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

/**
 * Сервис подключения к серверу эмулятора токена
 */
public class TokenEmulatorService {

    /**
     * TLS Логин на токен
     *
     * @param requestBody
     */
    public String sendRequestToTls(String requestBody, String url) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = setRequestBody(requestBody, url);

        HttpResponse response = httpClient.execute(httpPost);
        HttpEntity entity = response.getEntity();

        if (entity != null) {
            String responseString = EntityUtils.toString(entity);
            EntityUtils.consume(entity);

            return responseString;
        }

        return null;
    }

    @NotNull
    private HttpPost setRequestBody(String requestBody, String url) throws UnsupportedEncodingException {
        HttpPost httpPost = new HttpPost(url);

        // Установка заголовков запроса
        setHeaders(httpPost);

        // Установка тела запроса
        httpPost.setEntity(new StringEntity(requestBody, StandardCharsets.UTF_8));
        return httpPost;
    }

    private void setHeaders(HttpPost httpPost) {
        httpPost.setHeader("Accept-Encoding", "gzip,deflate");
        httpPost.setHeader("Content-Type", "text/xml; charset=UTF-8");
        httpPost.setHeader("Connection", "Keep-Alive");
        httpPost.setHeader("User-Agent", "Apache-HttpClient/4.1.1 (java 1.5)");
        httpPost.setHeader("Accept-Language", "ru-RU");
    }
}
