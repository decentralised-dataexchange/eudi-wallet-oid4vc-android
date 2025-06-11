import com.fasterxml.jackson.dataformat.xml.XmlMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.fasterxml.jackson.databind.JsonNode

object XmlFetchParserUtil {
    fun parseXmlToJsonString(xmlContent: String): String? {
        return try {
            val xmlMapper = XmlMapper().apply {
                registerKotlinModule()
            }
            val jsonNode: JsonNode = xmlMapper.readTree(xmlContent)
            jsonNode.toString() // JSON string output
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
