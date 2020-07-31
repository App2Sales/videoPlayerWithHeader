package io.flutter.plugins.videoplayer;

import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.crypto.AesCipherDataSource;

public class AESCipherDataSourceFactory implements DataSource.Factory {
    private final DataSource source;
    private final String secret;

    public AESCipherDataSourceFactory(DataSource source, String secret) {
        this.source = source;
        this.secret = secret;
    }

    @Override
    public DataSource createDataSource() {
        return new AesCipherDataSource(secret.getBytes(), this.source);
    }
}