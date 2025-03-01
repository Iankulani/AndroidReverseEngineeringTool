import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.nio.ByteBuffer

// Function to read file contents
fun readFile(filePath: String) {
    try {
        val file = File(filePath)
        val fileSize = file.length().toInt()

        val buffer = ByteArray(fileSize)
        FileInputStream(file).use { it.read(buffer) }

        println("File read successfully: $filePath")

        // Basic binary analysis (looking for common patterns)
        println("Searching for suspicious strings or patterns...")

        // Example pattern: searching for a string that may indicate malicious behavior
        for (i in 0 until fileSize - 4) {
            if (buffer.sliceArray(i until i + 4).contentEquals("exec".toByteArray())) {
                println("Suspicious pattern 'exec' found at offset $i")
            }
        }
    } catch (e: IOException) {
        println("Error opening file: $filePath")
    }
}

// Function to extract basic APK metadata
fun analyzeApk(apkPath: String) {
    try {
        val apkFile = File(apkPath)

        // Checking for the APK magic number (ZIP format)
        val buffer = ByteArray(4)
        FileInputStream(apkFile).use { it.read(buffer, 0, 4) }

        if (buffer[0] == 0x50.toByte() && buffer[1] == 0x4B.toByte() && buffer[2] == 0x03.toByte() && buffer[3] == 0x04.toByte()) {
            println("Valid APK file detected.")
        } else {
            println("This does not appear to be a valid APK file.")
        }

        // You can extend this to parse APK's "AndroidManifest.xml" or other files
    } catch (e: IOException) {
        println("Error opening APK file: $apkPath")
    }
}

// Main function
fun main() {
    print("Enter the path to the APK or binary file to analyze:")
    val filePath = readLine() ?: ""

    if (filePath.contains(".apk")) {
        println("Analyzing APK file...")
        analyzeApk(filePath)
    } else {
        println("Analyzing binary file...")
        readFile(filePath)
    }
}
