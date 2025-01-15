module.exports = {
    port: process.env.PORT || 3000,
    mongoUri: "mongodb+srv://veterano:wilson17@cluster0.ocdjg.mongodb.net/schedule-app-database?retryWrites=true&w=majority&appName=Cluster0",
    jwtSecret: "3732df64ca5d86bf5edfe0cf36cc9dd15243abbd83a2434fc52f429b80e60e46fe14664096590d7144582f43bdc68815ab72d428729f52e9cb2e046d4beeb7a2",
    // Add other production-specific configuration
};
