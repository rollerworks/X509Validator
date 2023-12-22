<?php

declare(strict_types=1);

/*
 * This file is part of the Rollerworks X509Validator package.
 *
 * (c) Sebastiaan Stok <s.stok@rollerscapes.net>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Rollerworks\Component\X509Validator;

use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Exception\Exception as OcspException;
use Ocsp\Ocsp;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Rollerworks\Component\X509Validator\Violation\CertificateIsRevoked;
use Rollerworks\Component\X509Validator\Violation\UnprocessablePEM;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

readonly class OCSPValidator
{
    private X509DataExtractor $extractor;
    private HttpClientInterface $httpClient;
    private CertificateLoader $certificateLoader;
    private CertificateInfo $certificateInfo;
    private LoggerInterface $logger;
    private CAResolver $caResolver;
    private Ocsp $ocsp;

    /**
     * @param HttpClientInterface|null $httpClient    If not provided will try to use the best possible
     *                                                HttpClient adapter
     * @param LoggerInterface|null     $logger        A logger for recording warnings and errors
     * @param CAResolver|null          $caResolver    Use a custom CAResolver that stores CAs
     * @param X509DataExtractor|null   $dataExtractor This should be reused by the validators
     *                                                to allow better caching
     * @param Ocsp|null                $ocsp          Only injected for testing
     */
    public function __construct(
        HttpClientInterface $httpClient = null,
        LoggerInterface $logger = null,
        CAResolver $caResolver = null,
        X509DataExtractor $dataExtractor = null,
        Ocsp $ocsp = null
    ) {
        if ($httpClient === null && ! class_exists(HttpClient::class)) {
            throw new \LogicException(sprintf('The "%s" class requires a "%s" instance, or that the Symfony HttpClient is available. Try running "composer require symfony/http-client".', self::class, HttpClientInterface::class));
        }

        $this->extractor = $dataExtractor ?? new X509DataExtractor();
        $this->httpClient = $httpClient ?? HttpClient::create();
        $this->logger = $logger ?? new NullLogger();
        $this->caResolver = $caResolver ?? new CAResolverImpl();
        $this->ocsp = $ocsp ?? new Ocsp();

        $this->certificateLoader = new CertificateLoader();
        $this->certificateInfo = new CertificateInfo();
    }

    /**
     * @param array<string, string> $caList
     *
     * @throws UnprocessablePEM
     * @throws CertificateIsRevoked
     */
    public function validateStatus(string $certificate, array $caList = []): void
    {
        $data = $this->extractor->extractRawData($certificate);
        $ca = $this->caResolver->resolve($certificate, $caList);

        // If there is no CA, no point in validating the OCSP.
        // Don't skip this stop when the CA list is empty, as CA's should still be valid.
        if ($ca === null) {
            return;
        }

        $certificateSeq = $this->certificateLoader->fromString($certificate);
        $issuerCertificate = $this->certificateLoader->fromString($ca->getContents());

        $ocspResponderUrl = $this->certificateInfo->extractOcspResponderUrl($certificateSeq);

        if ($ocspResponderUrl === '') {
            $this->logger->debug('No OCSP found for certificate.', ['data' => $data->allFields]);

            return;
        }

        $requestInfo = $this->certificateInfo->extractRequestInfo($certificateSeq, $issuerCertificate);
        $requestBody = $this->ocsp->buildOcspRequestBodySingle($requestInfo);

        try {
            $response = $this->getResponse($ocspResponderUrl, $requestBody);

            if ($response->getStatusCode() !== 200 || $response->getHeaders()['content-type'][0] !== Ocsp::OCSP_RESPONSE_MEDIATYPE) {
                $this->logger->warning('Unable to check OCSP status.', ['response' => $response]);

                return;
            }

            $ocspResponse = $this->ocsp->decodeOcspResponseSingle($response->getContent());

            if ($ocspResponse->isRevoked()) {
                throw new CertificateIsRevoked($ocspResponse->getRevokedOn(), $ocspResponse->getRevocationReason(), $ocspResponse->getCertificateSerialNumber());
            }
        } catch (OcspException | ExceptionInterface $exception) {
            $this->logger->error($exception->getMessage(), ['exception' => $exception]);
        }
    }

    private function getResponse(string $ocspResponderUrl, string $requestBody): ResponseInterface
    {
        return $this->httpClient->request('POST', $ocspResponderUrl, [
            'body' => $requestBody,
            'headers' => [
                'Content-Type' => Ocsp::OCSP_REQUEST_MEDIATYPE,
            ],
        ]);
    }
}
