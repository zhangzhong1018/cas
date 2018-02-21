package org.apereo.cas.validation;

import lombok.SneakyThrows;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.validation.xsd.gen.AttributesType;
import org.apereo.cas.validation.xsd.gen.AuthenticationSuccessType;
import org.apereo.cas.validation.xsd.gen.ObjectFactory;
import org.apereo.cas.validation.xsd.gen.ProxiesType;
import org.apereo.cas.validation.xsd.gen.ServiceResponseType;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;

/**
 * This is {@link CasProtocolValidationPayloadFactory}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
public class CasProtocolValidationPayloadFactory {
    private final ObjectFactory factory = new ObjectFactory();
    private final Marshaller marshaller;

    @SneakyThrows
    public CasProtocolValidationPayloadFactory() {
        final JAXBContext context = JAXBContext.newInstance("org.apereo.cas.validation.xsd.gen");
        marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
    }

    private String getModelAttributeOrNull(final Map<String, Object> validationModel, final String name) {
        if (validationModel.containsKey(name)) {
            return validationModel.get(name).toString();
        }
        return null;
    }

    @SneakyThrows
    public void createValidationSuccessPayload(final OutputStream outputStream, final Map<String, Object> validationModel) {
        final ServiceResponseType type = factory.createServiceResponseType();

        final AuthenticationSuccessType success = factory.createAuthenticationSuccessType();
        success.setUser(getModelAttributeOrNull(validationModel, CasViewConstants.MODEL_ATTRIBUTE_NAME_PRINCIPAL));
        success.setProxyGrantingTicket(getModelAttributeOrNull(validationModel, CasViewConstants.MODEL_ATTRIBUTE_NAME_PROXY_GRANTING_TICKET_IOU));

        final Collection<Authentication> chainedAuthentications = (Collection<Authentication>)
            validationModel.get(CasViewConstants.MODEL_ATTRIBUTE_NAME_CHAINED_AUTHENTICATIONS);

        if (chainedAuthentications != null) {
            final ProxiesType proxiesType = factory.createProxiesType();
            chainedAuthentications.stream()
                .map(auth -> auth.getPrincipal().getId())
                .forEach(proxy -> proxiesType.getProxy().add(proxy));
            success.setProxies(proxiesType);
        }

        final AttributesType attributesType = factory.createAttributesType();
        attributesType.setIsFromNewLogin(true);
        GregorianCalendar c = new GregorianCalendar();
        c.setTime(new Date());
        attributesType.setAuthenticationDate(DatatypeFactory.newInstance().newXMLGregorianCalendar(c));
        attributesType.setLongTermAuthenticationRequestTokenUsed(true);

        final QName qn = new QName("http://www.yale.edu/tp/cas", "misagh");
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        final Document doc = f.newDocumentBuilder().newDocument();
        final Node attributeEntry = doc.createElementNS(qn.getNamespaceURI(), qn.getLocalPart());
        attributeEntry.setPrefix("cas");
        attributeEntry.setTextContent("ValueIsHere");
        attributesType.getAny().add(attributeEntry);
        success.setAttributes(attributesType);
        type.setAuthenticationSuccess(success);


        final JAXBElement element = factory.createServiceResponse(type);


        marshaller.marshal(element, outputStream);
    }
}
