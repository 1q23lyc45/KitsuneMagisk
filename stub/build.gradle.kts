plugins {
    id("com.android.application")
    id("org.lsposed.lsparanoid")
}

lsparanoid {
    seed = if (RAND_SEED != 0) RAND_SEED else null
    includeDependencies = true
    global = true
}

android {
    namespace = "com.topjohnwu.magisk"

    val canary = !Config.version.contains(".")

    val url = if (canary) null
    else "https://huskydg.github.io/download/magisk/${Config.version}.apk"

    defaultConfig {
        applicationId = "io.github.huskydg.magisk"
        versionCode = 1
        versionName = "1.0"
        buildConfigField("String", "APK_URL", url?.let { "\"$it\"" } ?: "null" )
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = false
            proguardFiles("proguard-rules.pro")
        }
    }
}

setupStub()

dependencies {
    implementation(project(":app:shared"))
}
