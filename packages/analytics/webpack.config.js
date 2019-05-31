module.exports = {
    entry: {
        'aws-amplify-analytics.min': './cjs/index.js'
    },
    externals: [
        'react-native',
        '@aws-amplify/cache',
        '@aws-amplify/core',
        'aws-sdk/clients/pinpoint',
        'aws-sdk/clients/kinesis',
    ],
    output: {
        filename: '[name].js',
        path: __dirname + '/dist',
        library: 'aws_amplify_analytics',
        libraryTarget: 'umd',
        umdNamedDefine: true,
        devtoolModuleFilenameTemplate: require('../aws-amplify/webpack-utils').devtoolModuleFilenameTemplate
    },
    // Enable sourcemaps for debugging webpack's output.
    devtool: 'source-map',
    resolve: {
        extensions: ['.js', '.json']
    },
    mode: 'production',
    module: {
        rules: [
            // All output '.js' files will have any sourcemaps re-processed by 'source-map-loader'.
            //{ enforce: 'pre', test: /\.js$/, loader: 'source-map-loader' },
            {
                test: /\.js?$/,
                exclude: /node_modules/,
                use: [
                    "babel-loader",
                    {
                        loader: 'babel-loader',
                        options: {
                            presets: ['@babel/preset-env']
                        }
                    }
                ]
            }
        ]
    }
};
