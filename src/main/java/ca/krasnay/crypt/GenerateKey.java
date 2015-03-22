package ca.krasnay.crypt;

import java.util.ArrayList;

public class GenerateKey {

    public static void main(String[] args) {
        EncryptionService svc = new EncryptionServiceImpl(new ArrayList<String>());
        System.out.println(svc.generateKey());
    }
}
