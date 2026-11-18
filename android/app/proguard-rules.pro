# Release shrinking (R8). Shrink and optimize only: names stay readable in
# crash reports, and the code is open anyway.
-dontobfuscate

# gomobile bindings. The Go core (libgojni.so) finds these classes, fields
# and methods by name through JNI, so R8 must not remove or change them.
-keep class go.** { *; }
-keep class io.ashgate.mobile.** { *; }

# EncryptedSharedPreferences (androidx.security) runs on Tink, which reads
# its protobuf key sets through reflection. Kept whole: losing a field there
# would make the saved profiles unreadable.
-keep class androidx.security.crypto.** { *; }
-keep class com.google.crypto.tink.** { *; }

# Compile-time annotations and optional Tink paths (key download over HTTP,
# Joda time) that are not in the app and never run on Android.
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn com.google.api.client.**
-dontwarn org.joda.time.**
