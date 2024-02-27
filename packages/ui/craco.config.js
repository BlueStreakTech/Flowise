module.exports = {
    // devServer: {
    //     port: 8080,
    // },
    webpack: {
        configure: {
            module: {
                rules: [
                    {
                        test: /\.m?js$/,
                        resolve: {
                            fullySpecified: false
                        }
                    }
                ]
            },
            ignoreWarnings: [/Failed to parse source map/] // Ignore warnings about source maps
        }
    }
}
