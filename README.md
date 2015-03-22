# crypt

Crypt is a simple encryption library for Java that focuses on encrypting relatively short strings for storing in a database.

The central crypt component is the `EncryptionService`, which is configured with one or more keys stored in a configuration file on the application server. Data is encrypted using AES 128-bit encryption, then encoded to a string using Base64.

## Key Rotation

Key rotation is supported by configuring the encryption service with multiple keys. Each encrypted field is prefixed with a hash that indicates the key with which it was encrypted, so that you can add new keys without having to re-encrypt all your data. Data is always encrypted with the last configured key. Key rotation can therefore be performed as follows:

- generate a new key and add it to the encryption service configuration
- write code to read and re-encrypt each encrypted field on a schedule that makes sense for your application

## Key Generation

Crypt comes with a command-line utility to generate new keys:

    java -jar crypt.jar ca.krasnay.crypt.GenerateKey

## Spring Example

Here is an example implementation using Spring. First, generate a key and add it to your application properties file. This file should *not* be part of your source code, but rather should be created separately for each environment in which your application is stored. It should also have restrictive permissions such that only the user account that executes your application can access it. Finally, don't use *this* key; generate your own!

    encryptionKeys=2AXTw9lTJUhW0wqKDWMsvw==

Now create a configuration that defines the encryption service as a Spring bean:

    @Configuration
    public class EncryptionConfig {

        @Value("${encryptionKeys}")
        private String encryptionKeys;

        @Bean
        public EncryptionService encryptionService() {
            String[] keys = encryptionKeys.split("\\s*,\\s*");
            return new EncryptionServiceImpl(Arrays.asList(keys));
        }
    }

The encryption service is typically used in a DAO when reading or writing domain objects to/from the database:

    public class WidgetDaoImpl implements WidgetDao {

        @Inject
        private EncryptionService encryptionService;

        public void insert(Widget widget) {
            widget.setPrivateData(encryptionService.encryptString(widget.getPrivateData()));
            // insert widget
        }

        public Widget findById(int widgetId) {
            Widget widget = // find widget given widgetId
            widget.setPrivateData(encryptionService.decryptString(widget.getPrivateData()));
            return widget;
        }
    }

To rotate keys, generate a new key and append it to the `encryptionKeys` property:

    encryptionKeys=2AXTw9lTJUhW0wqKDWMsvw==,axfHfv2ofahVeAYH4pIutg==

Then, create a background task that reads and updates each widget via the DAO. Since the encryption service will accept any configured key to decrypt but will use the last configured key when encrypting, this will cause your data to be encrypted with the newest key.

## License

Crypt is licensed under the Apache License 2.0.


