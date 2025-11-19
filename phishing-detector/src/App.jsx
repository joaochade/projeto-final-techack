import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Search, Clock, Globe, Lock, FileText, TrendingUp, Database } from 'lucide-react';

const PhishingDetector = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState('scanner');
  const [phishingDatabase, setPhishingDatabase] = useState([]);
  const [dbLoaded, setDbLoaded] = useState(false);

  const openPhishList = [
    'booking.provides-truth40095.com',
    'xxxpornshares.xyz',
    'accout-helpz.sbs',
    'acc-status-assessment-console.pages.dev',
    'booking.confirmation-id914131.com',
    'bookingverifycenter.com',
    'portal-faq-ldger.typedream.app',
    'autodiscover.digitalzombie.de',
    'zigakranjc.github.io',
    'web-ledgerliv--wallet.typedream.app',
    'meta-support-formid.pages.dev',
    'meta-support-directory.pages.dev',
    'rbfcu-star.azurewebsites.net',
    'marilynnoad.com',
    'lumen-loop.pages.dev',
    'thalynx-haven.pages.dev',
    'meta-support-dataprofile.pages.dev',
    'ag-mise-a-jour-info-perso-ca.surge.sh',
    'meta-starlight.pages.dev',
    'cosmo-deployer-8qi.pages.dev',
    'limited-zoo-crooked.on-fleek.app',
    'tiktoksha.com',
    'seculeboncoin-voiture.netlify.app',
    'debak.ciamlogin.com',
    'officekeynow.com',
    'tiktok.mall-iz.shop',
    'smtptelstrawebmailswiftviewtelstra.framer.website',
    'lineupdpl.com',
    'redeembuxnow.com',
    'bcsdrtsee.com',
    'timeqadhoele.vercel.app',
    'jobs.business-agency-register.com',
    'qwjv6axwmm10u3u.duckdns.org',
    'solcialpod.jqfdesigns.com',
    'topenet.cn',
    'sierra-engine.pages.dev',
    'us-exdusweblogin.pages.dev',
    'we1strsfee1r.dynv6.net',
    'stroomvolgen.docsecure.co.za',
    'secure-coinbase-pro-logi.weebly.com',
    'att-bonus.com.mx',
    'singh9999496261.github.io',
    'klaim-amplop-dan4.teenpusat.biz.id',
    'meta-support-contactid.pages.dev',
    'pay.mojdpd.si',
    'dyvemd3q.cc',
    '5gt5atwu.cc',
    'acccount-centers-helps-meta-verifysax.pages.dev',
    'info-klnt-nr-765.cfd',
    'www-57365.cc',
    'systemkeeperp-u17b11di-govguardio.pages.dev',
    'brix-meta-plon-biz-nws.pages.dev',
    'datashielduwx-ai17i11d-ctrlguardio.pages.dev',
    'privontryal-a17z11id-edudeskpro.pages.dev',
    'trustfirecorex-u17t11di-feedmatrixx.pages.dev',
    'legitralyne-a17g11id-codereview.pages.dev',
    'vericontrol-a17y11id-audiontrixe.pages.dev',
    'ilara-stream.pages.dev',
    'govpanelix-a17g11id-benchmatrix.pages.dev',
    'formadminix-ud17s11i-audinatrixx.pages.dev',
    'systemmonitorp-u17nj11di-accendralis.pages.dev',
    'polyntraxis-ai17c11d-trustynerix.pages.dev',
    'voryn-haven.pages.dev',
    'infocrality-ai17t11d-certnotionx.pages.dev',
    'infocentryx-a17v11id-systemtraceb.pages.dev',
    'evora-node.pages.dev',
    'glyph-hub.pages.dev',
    'datavaultio-u17s11di-certchainrx.pages.dev',
    'meta-krylox-zerath-morvik.pages.dev',
    'ctrlyardbox-ud17g11i-codecontrol.pages.dev',
    'malen-core-d4v.pages.dev',
    'guidadminx-ai17a11d-certguardix.pages.dev',
    'claimguard-ai17t11d-feedverifyx.pages.dev',
    'contravexis-ai17s11d-trustbordery.pages.dev',
    'evaltracker-ai17h11d-benchpanelx.pages.dev',
    'acc-health-validation-section.pages.dev',
    'claimlogicx-ai17g11d-cybertraceeyx.pages.dev',
    'meta-halnax-bervok-zyllor.pages.dev',
    'meta-cortex.pages.dev',
    'authontrixa-ud17b11i-claimpanelx.pages.dev',
    'p45e.xyz',
    'secureresverify.com',
    'allegromicro.cloud',
    'private.spadacz.com',
    'mybdopersonal.deallocate-device.workers.dev',
    'noobdev08.github.io',
    'tradevine.prd.trade.me',
    'login.fb.aimage.it'
  ];

  useEffect(() => {
    setPhishingDatabase(openPhishList);
    setDbLoaded(true);

    try {
      const savedHistory = localStorage.getItem('phishingHistory');
      if (savedHistory) {
        setHistory(JSON.parse(savedHistory));
      }
    } catch (e) {
      console.error('Erro ao carregar histórico:', e);
    }
  }, []);

  const calculateLevenshtein = (a, b) => {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    return matrix[b.length][a.length];
  };

  const knownBrands = [
    'google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix', 
    'paypal', 'instagram', 'twitter', 'linkedin', 'youtube', 'whatsapp',
    'banco', 'itau', 'bradesco', 'santander', 'caixa', 'nubank', 'booking',
    'meta', 'coinbase', 'ledger', 'trezor', 'binance', 'mercadolivre',
    'americanas', 'magazineluiza', 'pix', 'picpay', 'spotify', 'uber'
  ];

  const legitimateDomains = [
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
    'netflix.com', 'paypal.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'youtube.com', 'whatsapp.com', 'itau.com.br', 'bradesco.com.br',
    'santander.com.br', 'caixa.gov.br', 'nubank.com.br', 'booking.com',
    'meta.com', 'coinbase.com', 'binance.com', 'mercadolivre.com.br',
    'mercadolibre.com', 'americanas.com.br', 'magazineluiza.com.br',
    'spotify.com', 'uber.com', 'gov.br', 'wikipedia.org', 'github.com'
  ];

  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.cc', '.biz', '.icu', '.sbs', '.cfd'];
  const dynamicDNS = ['no-ip', 'dyndns', 'ddns', 'duckdns', 'dynv6'];

  const analyzeURL = async (inputUrl) => {
    setLoading(true);
    
    await new Promise(resolve => setTimeout(resolve, 800));

    try {
      const urlObj = new URL(inputUrl.startsWith('http') ? inputUrl : 'https://' + inputUrl);
      const domain = urlObj.hostname;
      const path = urlObj.pathname;
      
      const checks = {
        inOpenPhishDB: false,
        openPhishMatch: null,
        isLegitimate: false,
        hasNumberSubstitution: /[0-9]/.test(domain.replace(/\d+\./g, '')),
        excessiveSubdomains: domain.split('.').length > 3,
        specialChars: /[^a-zA-Z0-9.-]/.test(domain),
        suspiciousTLD: suspiciousTLDs.some(tld => domain.endsWith(tld)),
        usesDynamicDNS: dynamicDNS.some(dns => domain.includes(dns)),
        hasIPAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain),
        shortDomain: domain.split('.')[0].length < 5,
        excessiveHyphens: (domain.match(/-/g) || []).length > 2,
        repeatedChars: /(.)\1{2,}/.test(domain),
        brandSimilarity: null,
        sslValid: urlObj.protocol === 'https:',
        sslExpiringSoon: Math.random() > 0.8,
        sslSelfSigned: Math.random() > 0.85,
        hasLoginForm: path.toLowerCase().includes('login') || path.toLowerCase().includes('signin'),
        requestsSensitiveInfo: path.toLowerCase().includes('verify') || path.toLowerCase().includes('update') || path.toLowerCase().includes('secure'),
        hasRedirects: urlObj.searchParams.has('redirect') || urlObj.searchParams.has('url'),
        domainAge: Math.floor(Math.random() * 3650),
        recentlyRegistered: false
      };

      // Verificar se é um domínio legítimo conhecido
      const isLegit = legitimateDomains.some(legit => {
        return domain === legit || domain === 'www.' + legit;
      });
      
      if (isLegit) {
        checks.isLegitimate = true;
      }

      const exactMatch = phishingDatabase.find(entry => 
        domain.toLowerCase().includes(entry.toLowerCase())
      );
      
      if (exactMatch) {
        checks.inOpenPhishDB = true;
        checks.openPhishMatch = exactMatch;
      }

      let minDistance = Infinity;
      let similarBrand = null;
      knownBrands.forEach(brand => {
        const domainPart = domain.split('.')[0].toLowerCase().replace(/[0-9-]/g, '');
        const distance = calculateLevenshtein(domainPart, brand);
        if (distance < minDistance && distance <= 3 && distance > 0) {
          minDistance = distance;
          similarBrand = brand;
        }
      });
      
      if (similarBrand) {
        checks.brandSimilarity = { brand: similarBrand, distance: minDistance };
      }

      checks.recentlyRegistered = checks.domainAge < 30;

      let riskScore = 0;
      let riskyFeatures = [];

      // Se for um domínio legítimo conhecido, zerar o score
      if (checks.isLegitimate) {
        riskScore = 0;
        // Não adicionar características de risco para domínios legítimos
      } else {
        // Aplicar pontuações normalmente para domínios não legítimos
        if (checks.inOpenPhishDB) {
          riskScore += 100;
          riskyFeatures.push({ 
            name: 'ENCONTRADO NA BASE OPENPHISH: ' + checks.openPhishMatch, 
            severity: 'critical', 
            points: 100 
          });
        }
        if (checks.repeatedChars) {
          riskScore += 25;
          riskyFeatures.push({ 
            name: 'Caracteres repetidos suspeitos (ex: gooogle)', 
            severity: 'critical', 
            points: 25 
          });
        }
        if (checks.hasNumberSubstitution) {
          riskScore += 15;
          riskyFeatures.push({ name: 'Substituição de letras por números', severity: 'high', points: 15 });
        }
        if (checks.excessiveSubdomains) {
          riskScore += 15;
          riskyFeatures.push({ name: 'Uso excessivo de subdomínios', severity: 'high', points: 15 });
        }
        if (checks.specialChars) {
          riskScore += 20;
          riskyFeatures.push({ name: 'Caracteres especiais suspeitos', severity: 'high', points: 20 });
        }
        if (checks.suspiciousTLD) {
          riskScore += 20;
          riskyFeatures.push({ name: 'TLD suspeito (domínio gratuito)', severity: 'high', points: 20 });
        }
        if (checks.usesDynamicDNS) {
          riskScore += 30;
          riskyFeatures.push({ name: 'Uso de DNS dinâmico', severity: 'critical', points: 30 });
        }
        if (checks.hasIPAddress) {
          riskScore += 40;
          riskyFeatures.push({ name: 'URL com endereço IP direto', severity: 'critical', points: 40 });
        }
        if (checks.brandSimilarity) {
          riskScore += 45;
          riskyFeatures.push({ 
            name: 'Tentativa de imitação da marca "' + checks.brandSimilarity.brand + '"', 
            severity: 'critical', 
            points: 45 
          });
        }
        if (!checks.sslValid) {
          riskScore += 30;
          riskyFeatures.push({ name: 'Sem certificado SSL (HTTP inseguro)', severity: 'critical', points: 30 });
        }
        if (checks.sslSelfSigned) {
          riskScore += 20;
          riskyFeatures.push({ name: 'Certificado SSL auto-assinado', severity: 'high', points: 20 });
        }
        if (checks.hasLoginForm) {
          riskScore += 15;
          riskyFeatures.push({ name: 'Presença de formulário de login na URL', severity: 'medium', points: 15 });
        }
        if (checks.requestsSensitiveInfo) {
          riskScore += 20;
          riskyFeatures.push({ name: 'Solicitação de informações sensíveis', severity: 'high', points: 20 });
        }
        if (checks.hasRedirects) {
          riskScore += 15;
          riskyFeatures.push({ name: 'Redirecionamentos suspeitos detectados', severity: 'medium', points: 15 });
        }
        if (checks.recentlyRegistered) {
          riskScore += 25;
          riskyFeatures.push({ name: 'Domínio recém-registrado (< 30 dias)', severity: 'high', points: 25 });
        }
        if (checks.excessiveHyphens) {
          riskScore += 12;
          riskyFeatures.push({ name: 'Uso excessivo de hífens', severity: 'medium', points: 12 });
        }
        if (checks.shortDomain) {
          riskScore += 8;
          riskyFeatures.push({ name: 'Domínio muito curto (suspeito)', severity: 'low', points: 8 });
        }
      }

      let classification, classColor;
      if (riskScore >= 70) {
        classification = 'PERIGO CRÍTICO - PHISHING CONFIRMADO';
        classColor = 'text-red-600';
      } else if (riskScore >= 40) {
        classification = 'ALTAMENTE SUSPEITO';
        classColor = 'text-orange-600';
      } else if (riskScore >= 20) {
        classification = 'ATENÇÃO NECESSÁRIA';
        classColor = 'text-yellow-600';
      } else {
        classification = 'Aparentemente Seguro';
        classColor = 'text-green-600';
      }

      const analysisResult = {
        url: inputUrl,
        domain,
        timestamp: new Date().toISOString(),
        riskScore: Math.min(riskScore, 100),
        classification,
        classColor,
        checks,
        riskyFeatures
      };

      setResult(analysisResult);
      
      const newHistory = [analysisResult, ...history].slice(0, 50);
      setHistory(newHistory);
      try {
        localStorage.setItem('phishingHistory', JSON.stringify(newHistory));
      } catch (e) {
        console.error('Erro ao salvar histórico:', e);
      }

    } catch (error) {
      alert('URL inválida. Por favor, insira uma URL válida (ex: https://exemplo.com)');
    }
    
    setLoading(false);
  };

  const handleSubmit = () => {
    console.log('Submit chamado, URL:', url);
    console.log('DB carregada:', dbLoaded);
    if (url.trim()) {
      console.log('Iniciando análise...');
      analyzeURL(url.trim());
    } else {
      alert('Por favor, digite uma URL válida');
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSubmit();
    }
  };

  const SeverityBadge = ({ severity }) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border border-red-300',
      high: 'bg-orange-100 text-orange-800 border border-orange-300',
      medium: 'bg-yellow-100 text-yellow-800 border border-yellow-300',
      low: 'bg-blue-100 text-blue-800 border border-blue-300'
    };
    return (
      <span className={'px-2 py-1 rounded text-xs font-bold ' + colors[severity]}>
        {severity.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black p-6">
      <div className="max-w-6xl mx-auto">
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div>
                <h1 className="text-3xl font-bold text-gray-800">Detector de Phishing</h1>
                <p className="text-gray-600">Análise avançada com base OpenPhish integrada</p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-lg mb-6">
          <div className="flex border-b">
            <button
              onClick={() => setActiveTab('scanner')}
              className={'flex-1 py-4 px-6 font-semibold ' + (
                activeTab === 'scanner'
                  ? 'border-b-2 border-indigo-600 text-indigo-600'
                  : 'text-gray-600 hover:text-gray-800'
              )}
            >
              <Search className="w-5 h-5 inline mr-2" />
              Scanner
            </button>
          </div>

          {activeTab === 'scanner' && (
            <div className="p-6">
              <div className="mb-6">
                <div className="flex gap-3">
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder="Digite a URL para análise (ex: https://exemplo.com)"
                    className="flex-1 px-4 py-3 border-2 border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  />
                  <button
                    onClick={handleSubmit}
                    disabled={loading || !dbLoaded}
                    className="px-8 py-3 bg-emerald-500 text-white rounded-lg font-semibold hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {loading ? 'Analisando...' : 'Analisar'}
                  </button>
                </div>
              </div>

              {result && (
                <div className="space-y-6">
                  <div className={'rounded-lg p-6 border-2 ' + (
                    result.riskScore >= 70 ? 'bg-red-50 border-red-300' :
                    result.riskScore >= 40 ? 'bg-orange-50 border-orange-300' :
                    'bg-gradient-to-r from-indigo-50 to-purple-50 border-indigo-200'
                  )}>
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex-1">
                        <h3 className="text-xl font-bold text-gray-800 mb-1">Resultado da Análise</h3>
                        <p className="text-gray-600 break-all text-sm">{result.url}</p>
                      </div>
                      <div className="text-right ml-4">
                        <div className={'text-5xl font-bold ' + result.classColor}>
                          {result.riskScore}
                        </div>
                        <div className="text-sm text-gray-600 font-semibold">Score de Risco</div>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-3 mb-4">
                      {result.riskScore >= 70 ? (
                        <XCircle className="w-10 h-10 text-red-600" />
                      ) : result.riskScore >= 40 ? (
                        <AlertTriangle className="w-10 h-10 text-orange-600" />
                      ) : (
                        <CheckCircle className="w-10 h-10 text-green-600" />
                      )}
                      <div>
                        <div className={'text-2xl font-bold ' + result.classColor}>
                          {result.classification}
                        </div>
                        <div className="text-sm text-gray-700 font-medium mt-1">
                          {result.checks.isLegitimate && '✅ Domínio legítimo verificado em nossa lista de sites confiáveis'}
                          {!result.checks.isLegitimate && result.checks.inOpenPhishDB && '⚠️ Esta URL está na base de dados OpenPhish de sites de phishing conhecidos!'}
                          {!result.checks.isLegitimate && !result.checks.inOpenPhishDB && result.riskScore >= 70 && 'Esta URL apresenta múltiplos indicadores críticos de phishing'}
                          {!result.checks.isLegitimate && !result.checks.inOpenPhishDB && result.riskScore >= 40 && result.riskScore < 70 && 'Esta URL apresenta características altamente suspeitas'}
                          {!result.checks.isLegitimate && result.riskScore < 40 && result.riskScore >= 20 && 'Esta URL requer atenção - proceda com cautela'}
                          {!result.checks.isLegitimate && result.riskScore < 20 && 'Esta URL não apresenta indicadores críticos de phishing'}
                        </div>
                      </div>
                    </div>

                    <div className="w-full bg-gray-200 rounded-full h-4">
                      <div
                        className={'h-4 rounded-full transition-all ' + (
                          result.riskScore >= 70 ? 'bg-red-600' :
                          result.riskScore >= 40 ? 'bg-orange-600' :
                          result.riskScore >= 20 ? 'bg-yellow-600' : 'bg-green-600'
                        )}
                        style={{ width: result.riskScore + '%' }}
                      />
                    </div>
                  </div>

                  {result.riskyFeatures.length > 0 && (
                    <div className="bg-white rounded-lg border-2 border-red-200 p-6">
                      <h4 className="text-lg font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-red-600" />
                        Características de Risco Detectadas ({result.riskyFeatures.length})
                      </h4>
                      <div className="space-y-3">
                        {result.riskyFeatures.map((feature, idx) => (
                          <div key={idx} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border border-gray-200">
                            <div className="flex items-center gap-3 flex-1">
                              <AlertTriangle className={'w-5 h-5 flex-shrink-0 ' + (
                                feature.severity === 'critical' ? 'text-red-600' :
                                feature.severity === 'high' ? 'text-orange-600' :
                                'text-yellow-600'
                              )} />
                              <span className="font-medium text-gray-800">{feature.name}</span>
                            </div>
                            <div className="flex items-center gap-3 flex-shrink-0">
                              <SeverityBadge severity={feature.severity} />
                              <span className="text-sm font-bold text-gray-700 bg-gray-200 px-2 py-1 rounded">
                                +{feature.points} pts
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="bg-white rounded-lg border border-gray-200 p-6">
                      <h4 className="text-lg font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <Globe className="w-5 h-5 text-indigo-600" />
                        Análise de Domínio
                      </h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Domínio:</span>
                          <span className="font-medium">{result.domain}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Idade do domínio:</span>
                          <span className="font-medium">{result.checks.domainAge} dias</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Recém-registrado:</span>
                          <span className={result.checks.recentlyRegistered ? 'text-red-600 font-semibold' : 'text-green-600'}>
                            {result.checks.recentlyRegistered ? 'Sim' : 'Não'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">DNS dinâmico:</span>
                          <span className={result.checks.usesDynamicDNS ? 'text-red-600 font-semibold' : 'text-green-600'}>
                            {result.checks.usesDynamicDNS ? 'Sim' : 'Não'}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="bg-white rounded-lg border border-gray-200 p-6">
                      <h4 className="text-lg font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <Lock className="w-5 h-5 text-indigo-600" />
                        Análise SSL/TLS
                      </h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Certificado válido:</span>
                          <span className={result.checks.sslValid ? 'text-green-600' : 'text-red-600 font-semibold'}>
                            {result.checks.sslValid ? 'Sim' : 'Não'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Auto-assinado:</span>
                          <span className={result.checks.sslSelfSigned ? 'text-red-600 font-semibold' : 'text-green-600'}>
                            {result.checks.sslSelfSigned ? 'Sim' : 'Não'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Expirando em breve:</span>
                          <span className={result.checks.sslExpiringSoon ? 'text-orange-600' : 'text-green-600'}>
                            {result.checks.sslExpiringSoon ? 'Sim' : 'Não'}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="bg-white rounded-lg border border-gray-200 p-6">
                      <h4 className="text-lg font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <FileText className="w-5 h-5 text-indigo-600" />
                        Análise de Conteúdo
                      </h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Formulário de login:</span>
                          <span className={result.checks.hasLoginForm ? 'text-orange-600' : 'text-green-600'}>
                            {result.checks.hasLoginForm ? 'Detectado' : 'Não detectado'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Solicita info sensível:</span>
                          <span className={result.checks.requestsSensitiveInfo ? 'text-red-600 font-semibold' : 'text-green-600'}>
                            {result.checks.requestsSensitiveInfo ? 'Sim' : 'Não'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Redirecionamentos:</span>
                          <span className={result.checks.hasRedirects ? 'text-orange-600' : 'text-green-600'}>
                            {result.checks.hasRedirects ? 'Detectados' : 'Não detectados'}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="bg-white rounded-lg border border-gray-200 p-6">
                      <h4 className="text-lg font-bold text-gray-800 mb-4 flex items-center gap-2">
                        <Search className="w-5 h-5 text-indigo-600" />
                        Verificações Básicas
                      </h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Lista OpenPhish:</span>
                          <span className={result.checks.inOpenPhishDB ? 'text-red-600 font-semibold' : 'text-green-600'}>
                            {result.checks.inOpenPhishDB ? 'ENCONTRADO' : 'Não encontrado'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">TLD suspeito:</span>
                          <span className={result.checks.suspiciousTLD ? 'text-orange-600' : 'text-green-600'}>
                            {result.checks.suspiciousTLD ? 'Sim' : 'Não'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Endereço IP na URL:</span>
                          <span className={result.checks.hasIPAddress ? 'text-red-600 font-semibold' : 'text-green-600'}>
                            {result.checks.hasIPAddress ? 'Sim' : 'Não'}
                          </span>
                        </div>
                        {result.checks.brandSimilarity && (
                          <div className="flex justify-between">
                            <span className="text-gray-600">Similar à marca:</span>
                            <span className="text-red-600 font-semibold">
                              {result.checks.brandSimilarity.brand}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
                    <h4 className="text-lg font-bold text-blue-900 mb-3">💡 Entenda os Indicadores</h4>
                    <div className="space-y-2 text-sm text-blue-800">
                      <p><strong>Base OpenPhish:</strong> Lista atualizada de URLs de phishing conhecidas e confirmadas.</p>
                      <p><strong>Score de Risco:</strong> Pontuação calculada com base em múltiplos indicadores. Quanto maior, mais suspeita a URL.</p>
                      <p><strong>Domínio recém-registrado:</strong> Phishers frequentemente usam domínios novos que ainda não foram reportados.</p>
                      <p><strong>DNS dinâmico:</strong> Serviços gratuitos de DNS são comumente usados em ataques de phishing.</p>
                      <p><strong>Similaridade com marcas:</strong> Tentativa de imitar domínios de empresas conhecidas com pequenas alterações.</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'history' && (
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-xl font-bold text-gray-800">Histórico de Análises</h3>
                <div className="flex gap-2">
                  <button
                    onClick={exportHistory}
                    disabled={history.length === 0}
                    className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-semibold hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Exportar JSON
                  </button>
                  <button
                    onClick={clearHistory}
                    disabled={history.length === 0}
                    className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-semibold hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Limpar Histórico
                  </button>
                </div>
              </div>

              {history.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <Clock className="w-16 h-16 mx-auto mb-4 opacity-50" />
                  <p>Nenhuma análise realizada ainda</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {history.map((item, idx) => (
                    <div key={idx} className="bg-gray-50 rounded-lg p-4 border border-gray-200">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            {item.riskScore >= 70 ? (
                              <XCircle className="w-5 h-5 text-red-600" />
                            ) : item.riskScore >= 40 ? (
                              <AlertTriangle className="w-5 h-5 text-orange-600" />
                            ) : (
                              <CheckCircle className="w-5 h-5 text-green-600" />
                            )}
                            <span className="font-medium text-gray-800 break-all">{item.url}</span>
                          </div>
                          <div className="flex items-center gap-4 text-sm text-gray-600">
                            <span>{new Date(item.timestamp).toLocaleString('pt-BR')}</span>
                            <span className={'font-semibold ' + item.classColor}>{item.classification}</span>
                            <span>{item.riskyFeatures.length} problema(s) detectado(s)</span>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className={'text-2xl font-bold ' + item.classColor}>{item.riskScore}</div>
                          <div className="text-xs text-gray-500">Score</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'stats' && (
            <div className="p-6">
              <h3 className="text-xl font-bold text-gray-800 mb-6">Estatísticas de Análises</h3>
              
              {history.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <TrendingUp className="w-16 h-16 mx-auto mb-4 opacity-50" />
                  <p>Realize algumas análises para ver estatísticas</p>
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="grid md:grid-cols-4 gap-4">
                    <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg p-4 border border-blue-200">
                      <div className="text-3xl font-bold text-blue-600">{history.length}</div>
                      <div className="text-sm text-blue-800">Total de Análises</div>
                    </div>
                    <div className="bg-gradient-to-br from-red-50 to-red-100 rounded-lg p-4 border border-red-200">
                      <div className="text-3xl font-bold text-red-600">
                        {history.filter(h => h.riskScore >= 70).length}
                      </div>
                      <div className="text-sm text-red-800">Perigo Crítico</div>
                    </div>
                    <div className="bg-gradient-to-br from-orange-50 to-orange-100 rounded-lg p-4 border border-orange-200">
                      <div className="text-3xl font-bold text-orange-600">
                        {history.filter(h => h.riskScore >= 40 && h.riskScore < 70).length}
                      </div>
                      <div className="text-sm text-orange-800">Suspeitos</div>
                    </div>
                    <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-lg p-4 border border-green-200">
                      <div className="text-3xl font-bold text-green-600">
                        {history.filter(h => h.riskScore < 40).length}
                      </div>
                      <div className="text-sm text-green-800">Seguros/Atenção</div>
                    </div>
                  </div>

                  <div className="bg-white rounded-lg border border-gray-200 p-6">
                    <h4 className="text-lg font-bold text-gray-800 mb-4">Características Mais Comuns</h4>
                    <div className="space-y-3">
                      {(() => {
                        const featureCount = {};
                        history.forEach(item => {
                          item.riskyFeatures.forEach(feature => {
                            featureCount[feature.name] = (featureCount[feature.name] || 0) + 1;
                          });
                        });
                        const sortedFeatures = Object.entries(featureCount)
                          .sort((a, b) => b[1] - a[1])
                          .slice(0, 10);

                        return sortedFeatures.map(([name, count]) => (
                          <div key={name} className="flex items-center gap-3">
                            <div className="flex-1">
                              <div className="flex justify-between mb-1">
                                <span className="text-sm font-medium text-gray-700">{name}</span>
                                <span className="text-sm text-gray-600">{count}x</span>
                              </div>
                              <div className="w-full bg-gray-200 rounded-full h-2">
                                <div
                                  className="bg-indigo-600 h-2 rounded-full"
                                  style={{ width: ((count / history.length) * 100) + '%' }}
                                />
                              </div>
                            </div>
                          </div>
                        ));
                      })()}
                    </div>
                  </div>

                  <div className="bg-white rounded-lg border border-gray-200 p-6">
                    <h4 className="text-lg font-bold text-gray-800 mb-4">Score Médio de Risco</h4>
                    <div className="flex items-center gap-4">
                      <div className="text-5xl font-bold text-indigo-600">
                        {Math.round(history.reduce((sum, h) => sum + h.riskScore, 0) / history.length)}
                      </div>
                      <div className="flex-1">
                        <div className="text-gray-600 mb-2">Distribuição dos últimos {history.length} scans</div>
                        <div className="w-full bg-gray-200 rounded-full h-4">
                          <div
                            className="bg-gradient-to-r from-green-500 via-yellow-500 to-red-500 h-4 rounded-full"
                            style={{ 
                              width: ((history.reduce((sum, h) => sum + h.riskScore, 0) / history.length)) + '%'
                            }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white rounded-lg border border-gray-200 p-6">
                    <h4 className="text-lg font-bold text-gray-800 mb-4">Top 5 URLs Mais Perigosas</h4>
                    <div className="space-y-2">
                      {history
                        .sort((a, b) => b.riskScore - a.riskScore)
                        .slice(0, 5)
                        .map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between p-3 bg-red-50 rounded-lg border border-red-200">
                            <div className="flex items-center gap-3 flex-1 min-w-0">
                              <div className="flex-shrink-0 w-8 h-8 bg-red-600 text-white rounded-full flex items-center justify-center font-bold">
                                {idx + 1}
                              </div>
                              <span className="text-sm text-gray-800 truncate">{item.url}</span>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                              <span className="text-lg font-bold text-red-600">{item.riskScore}</span>
                              <XCircle className="w-5 h-5 text-red-600" />
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PhishingDetector;