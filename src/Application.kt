package sandbox

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.*
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.jackson.jackson
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import io.ktor.util.hex
import java.math.BigInteger
import java.security.MessageDigest

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

fun String.hash(algoName: String): String {
    val md = MessageDigest.getInstance(algoName)
    return BigInteger(1, md.digest(toByteArray())).toString(16).padStart(32, '0')
}

@KtorExperimentalAPI
fun Application.bank() {
//    install(ContentNegotiation) {
//        jackson {  }
//    }
    install(StatusPages) {
        exception<Throwable> { e ->
            call.respondText(e.localizedMessage, ContentType.Text.Plain, HttpStatusCode.InternalServerError)
        }
    }
    install(Authentication) {
        basic("basic") {
            realm = ""
            validate { credentials ->
                when {
                    credentials.name == "Louis" && credentials.password == "pass" -> UserIdPrincipal("Louis")
                    else -> null
                }
            }
        }
        val usersInMyRealmToHA1: Map<String, ByteArray> = mapOf(
            "Louis" to hex("Louis:MyRealm:pass".hash("MD5"))
        )
        digest("digest") {
            realm = "MyRealm"
            userNameRealmPasswordDigestProvider = { userName, _ ->
                usersInMyRealmToHA1[userName]
            }
        }
        form("form") {
            challenge = FormAuthChallenge.Unauthorized
            passwordParamName = "password"
            userParamName = "username"
            validate { credentials ->
                when {
                    credentials.name == "Louis" && credentials.password == "pass" -> UserIdPrincipal("Louis")
                    else -> null
                }
            }
        }
    }
    routing {
        authenticate("form") {
            route("account") {
                post {
                    call.respond(HttpStatusCode.OK, "connected")
                }
            }
        }
        post {
            call.respond(HttpStatusCode.OK, "worked")
        }
    }
}

// todo : get principal
// todo : status pages
// todo : form json authenticate
// todo : authentication startegy
