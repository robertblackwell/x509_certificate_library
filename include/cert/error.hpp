#ifndef cert_error_include_hpp
#define cert_error_include_hpp
#include <string>
#include <openssl/err.h>

namespace Cert {

    /**
     * Error handlers for Cert::x509 functions - use the following macro to report an error, mainly SSL/X509 errors.
     * Captures file and line number, reads crypto error messages,
     * packs all that into a Cert::x509::Exception and throws that exception
     */
    #define X509_TRIGGER_ERROR(msg) Cert::x509::errorHandler(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg)

    /**
    * In the following macros the msg argument can be a stream expression of the form
    *
    * "something" << "somethingelse" << variable
    *
    * must not start or end with a <<
     */
    #define IFTRUE_THROW(value, msg) \
        do { \
            if(value) { \
                std::stringstream messageStream; \
                messageStream << msg ; \
                Cert::errorHandler(__PRETTY_FUNCTION__, __FILE__, __LINE__, messageStream.str()); \
            } \
        } while(0);
        
    #define IFFALSE_THROW(value, msg) \
        do { \
            if(!(value)) { \
                std::stringstream messageStream; \
                messageStream << msg ; \
                Cert::errorHandler(__PRETTY_FUNCTION__, __FILE__, __LINE__, messageStream.str()); \
            } \
        } while(0);

    #define THROW(msg) \
        do { \
            std::stringstream messageStream; \
            messageStream << msg ; \
            Cert::errorHandler(__PRETTY_FUNCTION__, __FILE__, __LINE__, messageStream.str()); \
        } while(0);

    #define NOT_IMPLEMENTED() Cert::errorHandler(__PRETTY_FUNCTION__, __FILE__, __LINE__, "function not implemented"); 


    namespace x509 {
        void errorHandler (std::string func, std::string file, int lineno, std::string msg);
    }
    void errorHandler (std::string func, std::string file, int lineno, std::string msg);
    /**
    * \brief Custom exception class for functions in namespace Cert::x509
    */
    class Exception : public std::exception
    {
        public:
            Exception(std::string message);
            const char* what() const noexcept;
        private:
            std::string x509_ErrMessage;
    };

} //namespace Cert

#endif
