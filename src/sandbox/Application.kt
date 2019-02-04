package sandbox

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.*
import io.ktor.features.ContentNegotiation
import io.ktor.http.HttpStatusCode
import io.ktor.jackson.jackson
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import io.ktor.util.hex
import org.jetbrains.exposed.dao.EntityID
import org.jetbrains.exposed.dao.IntEntity
import org.jetbrains.exposed.dao.IntEntityClass
import org.jetbrains.exposed.dao.IntIdTable
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.transactions.TransactionManager
import org.jetbrains.exposed.sql.transactions.transaction
import java.io.File
import java.math.BigInteger
import java.security.MessageDigest
import java.sql.Connection

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

fun String.hash(algoName: String): String {
    val md = MessageDigest.getInstance(algoName)
    return BigInteger(1, md.digest(toByteArray())).toString(16).padStart(32, '0')
}

object Users : IntIdTable() {
    val userName = varchar("username", 50)
    val password = varchar("password", 64)

    fun contains(userName: String, password: String) = transaction {
        User.count(
            (Users.userName eq userName) and (Users.password eq password.toSHA256())
        ) > 0
    }
}


class User(id: EntityID<Int>) : IntEntity(id) {
    companion object : IntEntityClass<User>(Users)
    var userName by Users.userName
    var password by Users.password
}

data class UserPost(val userName: String, val password: String)


fun initDB() {
    val databaseFile = File("data.db")
    if (databaseFile.exists()) {
        databaseFile.delete()
    }
    Database.connect("jdbc:sqlite:data.db", "org.sqlite.JDBC")
    TransactionManager.manager.defaultIsolationLevel = Connection.TRANSACTION_SERIALIZABLE
    transaction {
        SchemaUtils.create(Users)
    }
}

fun String.toSHA256(): String {
    return MessageDigest.getInstance("SHA-256").digest(toByteArray()).joinToString("") { "%02x".format(it) }
}

@KtorExperimentalAPI
fun Application.module() {
    initDB()
    install(ContentNegotiation) {
        jackson{}
    }
    install(Authentication) {
        basic("basic") {
            realm = ""
            validate { credentials ->
                when {
                    Users.contains(credentials.name, credentials.password) -> UserIdPrincipal(credentials.name)
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
                    Users.contains(credentials.name, credentials.password) -> UserIdPrincipal(credentials.name)
                    else -> null
                }
            }
        }
    }
    routing {
        authenticate("form") {
            route("account") {
                post {
                    val principal = call.authentication.principal<UserIdPrincipal>()?.name ?: "guest"
                    call.respond(HttpStatusCode.OK, "Welcome $principal")
                }
            }
        }
        post("inscription") {
            val userPost = call.receive<UserPost>()
            transaction {
                User.new {
                    userName = userPost.userName
                    password = userPost.password.toSHA256()
                }
            }
            call.respond(HttpStatusCode.Created, "created")
        }
    }
}

// todo : status pages
// todo sessions
