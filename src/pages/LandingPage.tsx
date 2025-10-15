import { Link } from "react-router-dom";
import {
  Shield,
  Brain,
  Lock,
  Eye,
  Zap,
  Search,
  AlertTriangle,
  Scan,
  Network,
  BarChart3,
} from "lucide-react";
import { motion } from "motion/react";
import { GlassmorphicNav } from "../components/GlassmorphicNav";
import CardSwap, { Card } from "../components/CardSwap";
import SplitText from "../components/SplitText";
import Hyperspeed from "../components/Hyperspeed";
import DecryptedText from "../components/DecryptedText";
const handleAnimationComplete = () => {
  console.log("All letters have animated!");
};
import ScrollReveal from "../components/ScrollReveal";
import BlurText from "../components/BlurText";
import LogoLoop from "../components/LogoLoop";
import {
  SiReact,
  SiNextdotjs,
  SiTypescript,
  SiTailwindcss,
} from "react-icons/si";
import SpotlightCard from "../components/SpotlightCard";
const techLogos = [
  { node: <SiReact />, title: "React", href: "https://react.dev" },
  { node: <SiNextdotjs />, title: "Next.js", href: "https://nextjs.org" },
  {
    node: <SiTypescript />,
    title: "TypeScript",
    href: "https://www.typescriptlang.org",
  },
  {
    node: <SiTailwindcss />,
    title: "Tailwind CSS",
    href: "https://tailwindcss.com",
  },
];

// Alternative with image sources
const imageLogos = [
  {
    src: "/logos/company1.png",
    alt: "Company 1",
    href: "https://company1.com",
  },
  {
    src: "/logos/company2.png",
    alt: "Company 2",
    href: "https://company2.com",
  },
  {
    src: "/logos/company3.png",
    alt: "Company 3",
    href: "https://company3.com",
  },
];
export function LandingPage() {
  return (
    <div className="min-h-screen relative bg-black">
      {/* Hyperspeed Background */}
      <div className="fixed inset-0 z-0">
        <Hyperspeed
          effectOptions={{
            onSpeedUp: () => {},
            onSlowDown: () => {},
            distortion: "mountainDistortion",
            length: 400,
            roadWidth: 9,
            islandWidth: 2,
            lanesPerRoad: 3,
            fov: 90,
            fovSpeedUp: 150,
            speedUp: 2,
            carLightsFade: 0.4,
            totalSideLightSticks: 50,
            lightPairsPerRoadWay: 50,
            shoulderLinesWidthPercentage: 0.05,
            brokenLinesWidthPercentage: 0.1,
            brokenLinesLengthPercentage: 0.5,
            lightStickWidth: [0.12, 0.5],
            lightStickHeight: [1.3, 1.7],

            movingAwaySpeed: [60, 80],
            movingCloserSpeed: [-120, -160],
            carLightsLength: [400 * 0.05, 400 * 0.15],
            carLightsRadius: [0.05, 0.14],
            carWidthPercentage: [0.3, 0.5],
            carShiftX: [-0.2, 0.2],
            carFloorSeparation: [0.05, 1],
            colors: {
              roadColor: 0x080808,
              islandColor: 0x0a0a0a,
              background: 0x000000,
              shoulderLines: 0x131318,
              brokenLines: 0x131318,
              leftCars: [0xff102a, 0xeb383e, 0xff102a],
              rightCars: [0xdadafa, 0xbebae3, 0x8f97e4],
              sticks: 0xdadafa,
            },
          }}
        />
      </div>

      {/* Navigation */}
      <GlassmorphicNav />

      {/* Main Content */}
      <div className="relative z-10 px-12 min-h-screen flex items-center justify-center">
        <div className="max-w-7xl mx-auto">
          {/* Hero Section */}
          <div className="text-center space-y-8 mb-32">
            <div className="w-full flex justify-center">
              <h1 className="text-8xl leading-tight tracking-tight text-center font-satoshi font-black">
                <BlurText
                  text="Intelligent Vulnerability"
                  delay={150}
                  animateBy="words"
                  direction="top"
                  onAnimationComplete={handleAnimationComplete}
                  className="font-satoshi font-bold text-white text-6xl md:text-7xl lg:text-8xl text-center mx-auto block"
                />
                {/* <span className="block text-white">Intelligent Vulnerability</span>
                <span className="text-white/30 block mt-2">Detection</span> */}
              </h1>
            </div>
            <SplitText
              text="Leverage AI-powered analysis and real-time threat intelligence to protect your digital infrastructure"
              className="text-2xl font-semibold font-satoshi text-center  text-white"
              delay={10}
              duration={2}
              ease="power3.out"
              splitType="chars"
              from={{ opacity: 0, y: 40 }}
              to={{ opacity: 1, y: 0 }}
              threshold={0.1}
              rootMargin="-100px"
              textAlign="center"
              onLetterAnimationComplete={handleAnimationComplete}
            />

            {/* CTAs */}
            <div className="flex items-center justify-center gap-6 pt-8">
              <Link to="/scan">
                <motion.button
                  className="px-8 py-4 bg-black/70 backdrop-blur-md rounded-full border border-white/30 text-white hover:bg-black/80 hover:shadow-[0_0_30px_rgba(255,255,255,0.15)] transition-all shadow-lg text-lg"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  Start Scanning →
                </motion.button>
              </Link>
              <Link to="/dashboard">
                <motion.button
                  className="px-8 py-4 bg-white backdrop-blur-md rounded-full border border-white text-black hover:bg-gray-100 hover:shadow-[0_0_30px_rgba(255,255,255,0.3)] transition-all shadow-lg text-lg font-satoshi font-bold"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  View Dashboard
                </motion.button>
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Features Section with DecryptedText and CardSwap */}
      <section className="relative py-32 px-12">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            {/* Left Side - DecryptedText Content */}
            <div className="space-y-8 pointer-events-auto">
              <div className="space-y-6">
                <h2 className="text-5xl md:text-6xl lg:text-7xl font-black text-white font-satoshi leading-tight">
                  <DecryptedText
                    text="Advanced Security Features"
                    speed={110}
                    sequential={true}
                    animateOn="view"
                    revealDirection="end"
                    useOriginalCharsOnly={false}
                    maxIterations={20}
                    characters="ABCD1234!?"
                    className="text-white font-black"
                    parentClassName="text-8xl md:text-6xl lg:text-7xl font-black font-satoshi leading-tight"
                    encryptedClassName="text-white/30"
                  />
                </h2>
                <div className="space-y-8">
                  <p className="text-lg md:text-xl lg:text-2xl text-white/90 leading-relaxed font-black font-satoshi">
                    <DecryptedText
                      text="Our comprehensive security platform combines cutting-edge AI technology with real-time threat intelligence to provide unparalleled protection for your digital infrastructure."
                      speed={124}
                      animateOn="view"
                      maxIterations={15}
                      characters="ABCD1234!?"
                      className="text-white/90 font-black font-satoshi"
                      parentClassName="text-lg md:text-xl lg:text-2xl leading-relaxed font-black font-satoshi"
                      encryptedClassName="text-white/20"
                    />
                  </p>
                  <p className="text-base md:text-lg lg:text-xl text-white/80 leading-relaxed font-bold font-satoshi">
                    <DecryptedText
                      text="From automated vulnerability scanning to intelligent threat analysis, each feature is designed to keep you one step ahead of emerging cybersecurity challenges."
                      speed={150}
                      animateOn="view"
                      maxIterations={15}
                      characters="ABCD1234!?"
                      className="text-white/80 font-bold font-satoshi"
                      parentClassName="text-base md:text-lg lg:text-xl leading-relaxed font-bold font-satoshi"
                      encryptedClassName="text-white/20"
                    />
                  </p>
                </div>
              </div>

              {/* Feature Stats with SpotlightCard */}
            </div>

            {/* Right Side - CardSwap */}
            <div className="pointer-events-none">
              <div style={{ height: "500px", position: "relative" }}>
                <CardSwap
                  cardDistance={60}
                  verticalDistance={70}
                  delay={3000}
                  pauseOnHover={true}
                  skewAmount={8}
                  height={400}
                >
                  <Card>
                    <div className="relative p-8 h-full bg-gradient-to-br from-gray-500/25 via-black/70 to-gray-900/40 backdrop-blur-xl border border-gray-500/30 rounded-2xl shadow-2xl hover:shadow-gray-500/20 transition-all duration-500 group overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-gray-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                      <div className="relative z-10">
                        <div className="flex items-center gap-4 mb-6">
                          <div className="w-16 h-16 rounded-xl bg-gray-500/20 backdrop-blur-sm border border-gray-400/40 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                            <BarChart3 className="w-8 h-8 text-gray-400" />
                          </div>
                          <h3 className="text-3xl font-black text-white group-hover:text-gray-100 transition-colors duration-300 font-satoshi">
                            Dashboard
                          </h3>
                        </div>
                        <p className="text-white/80 leading-relaxed text-lg md:text-xl group-hover:text-white/90 transition-colors duration-300 font-bold font-satoshi">
                          Comprehensive security overview with real-time
                          metrics, vulnerability trends, and system health
                          monitoring in one unified interface.
                        </p>
                        <div className="absolute bottom-4 right-4 w-3 h-3 bg-gray-400 rounded-full animate-pulse" />
                      </div>
                    </div>
                  </Card>
                  <Card>
                    <div className="relative p-8 h-full bg-gradient-to-br from-blue-500/25 via-black/70 to-blue-900/40 backdrop-blur-xl border border-blue-500/30 rounded-2xl shadow-2xl hover:shadow-blue-500/20 transition-all duration-500 group overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                      <div className="relative z-10">
                        <div className="flex items-center gap-4 mb-6">
                          <div className="w-16 h-16 rounded-xl bg-blue-500/20 backdrop-blur-sm border border-blue-400/40 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                            <Scan className="w-8 h-8 text-blue-400" />
                          </div>
                          <h3 className="text-3xl font-black text-white group-hover:text-blue-100 transition-colors duration-300 font-satoshi">
                            AI Scanner
                          </h3>
                        </div>
                        <p className="text-white/80 leading-relaxed text-lg md:text-xl group-hover:text-white/90 transition-colors duration-300 font-bold font-satoshi">
                          Advanced vulnerability scanning powered by machine
                          learning algorithms to detect threats,
                          misconfigurations, and security gaps across your
                          infrastructure.
                        </p>
                        <div className="absolute bottom-4 right-4 w-3 h-3 bg-blue-400 rounded-full animate-pulse" />
                      </div>
                    </div>
                  </Card>
                  <Card>
                    <div className="relative p-8 h-full bg-gradient-to-br from-red-500/25 via-black/70 to-red-900/40 backdrop-blur-xl border border-red-500/30 rounded-2xl shadow-2xl hover:shadow-red-500/20 transition-all duration-500 group overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                      <div className="relative z-10">
                        <div className="flex items-center gap-4 mb-6">
                          <div className="w-16 h-16 rounded-xl bg-red-500/20 backdrop-blur-sm border border-red-400/40 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                            <AlertTriangle className="w-8 h-8 text-red-400" />
                          </div>
                          <h3 className="text-3xl font-black text-white group-hover:text-red-100 transition-colors duration-300 font-satoshi">
                            Threat Intelligence
                          </h3>
                        </div>
                        <p className="text-white/80 leading-relaxed text-lg md:text-xl group-hover:text-white/90 transition-colors duration-300 font-bold font-satoshi">
                          Stay ahead of emerging threats with real-time
                          intelligence feeds, attack pattern analysis, and
                          proactive security recommendations.
                        </p>
                        <div className="absolute bottom-4 right-4 w-3 h-3 bg-red-400 rounded-full animate-pulse" />
                      </div>
                    </div>
                  </Card>
                  <Card>
                    <div className="relative p-8 h-full bg-gradient-to-br from-purple-500/25 via-black/70 to-purple-900/40 backdrop-blur-xl border border-purple-500/30 rounded-2xl shadow-2xl hover:shadow-purple-500/20 transition-all duration-500 group overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-purple-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                      <div className="relative z-10">
                        <div className="flex items-center gap-4 mb-6">
                          <div className="w-16 h-16 rounded-xl bg-purple-500/20 backdrop-blur-sm border border-purple-400/40 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                            <Brain className="w-8 h-8 text-purple-400" />
                          </div>
                          <h3 className="text-3xl font-black text-white group-hover:text-purple-100 transition-colors duration-300 font-satoshi">
                            AI Assistant
                          </h3>
                        </div>
                        <p className="text-white/80 leading-relaxed text-lg md:text-xl group-hover:text-white/90 transition-colors duration-300 font-bold font-satoshi">
                          Intelligent security companion that provides instant
                          analysis, remediation guidance, and answers to complex
                          cybersecurity questions.
                        </p>
                        <div className="absolute bottom-4 right-4 w-3 h-3 bg-purple-400 rounded-full animate-pulse" />
                      </div>
                    </div>
                  </Card>
                  <Card>
                    <div className="relative p-8 h-full bg-gradient-to-br from-cyan-500/25 via-black/70 to-cyan-900/40 backdrop-blur-xl border border-cyan-500/30 rounded-2xl shadow-2xl hover:shadow-cyan-500/20 transition-all duration-500 group overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                      <div className="relative z-10">
                        <div className="flex items-center gap-4 mb-6">
                          <div className="w-16 h-16 rounded-xl bg-cyan-500/20 backdrop-blur-sm border border-cyan-400/40 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                            <Network className="w-8 h-8 text-cyan-400" />
                          </div>
                          <h3 className="text-3xl font-black text-white group-hover:text-cyan-100 transition-colors duration-300 font-satoshi">
                            Network Protection
                          </h3>
                        </div>
                        <p className="text-white/80 leading-relaxed text-lg md:text-xl group-hover:text-white/90 transition-colors duration-300 font-bold font-satoshi">
                          Multi-layered defense system with intrusion detection,
                          traffic analysis, and automated response capabilities
                          to secure your network perimeter.
                        </p>
                        <div className="absolute bottom-4 right-4 w-3 h-3 bg-cyan-400 rounded-full animate-pulse" />
                      </div>
                    </div>
                  </Card>
                  <Card>
                    <div className="relative p-8 h-full bg-gradient-to-br from-yellow-500/25 via-black/70 to-yellow-900/40 backdrop-blur-xl border border-yellow-500/30 rounded-2xl shadow-2xl hover:shadow-yellow-500/20 transition-all duration-500 group overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-yellow-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                      <div className="relative z-10">
                        <div className="flex items-center gap-4 mb-6">
                          <div className="w-16 h-16 rounded-xl bg-yellow-500/20 backdrop-blur-sm border border-yellow-400/40 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                            <Search className="w-8 h-8 text-yellow-400" />
                          </div>
                          <h3 className="text-3xl font-black text-white group-hover:text-yellow-100 transition-colors duration-300 font-satoshi">
                            Documentation
                          </h3>
                        </div>
                        <p className="text-white/80 leading-relaxed text-lg md:text-xl group-hover:text-white/90 transition-colors duration-300 font-bold font-satoshi">
                          Comprehensive guides, API references, and best
                          practices to help you maximize your security posture
                          and platform capabilities.
                        </p>
                        <div className="absolute bottom-4 right-4 w-3 h-3 bg-yellow-400 rounded-full animate-pulse" />
                      </div>
                    </div>
                  </Card>
                </CardSwap>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer with Enhanced Feature Icons */}
      <footer className="relative mt-64 pointer-events-none">
        <div className="max-w-7xl mx-auto px-12 py-16">
          {/* Spacer to push content to bottom */}
          <div className="h-96"></div>

          {/* Footer Bottom */}
          <div className="mt-32 pt-8 text-center pointer-events-auto relative z-10">
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-8">
              <motion.div
                className="group cursor-pointer text-center"
                whileHover={{ scale: 1.05 }}
                transition={{ duration: 0.2 }}
              >
                <div className="w-20 h-20 rounded-2xl bg-white/8 backdrop-blur-xl border border-white/30 flex items-center justify-center hover:bg-white/15 hover:border-white/50 transition-all duration-300 shadow-lg mx-auto mb-4">
                  <Shield className="w-9 h-9 text-white" />
                </div>
                <h3 className="text-white font-semibold text-lg mb-2">
                  Advanced Protection
                </h3>
              </motion.div>

              <motion.div
                className="group cursor-pointer text-center"
                whileHover={{ scale: 1.05 }}
                transition={{ duration: 0.2 }}
              >
                <div className="w-20 h-20 rounded-2xl bg-white/8 backdrop-blur-xl border border-white/30 flex items-center justify-center hover:bg-white/15 hover:border-white/50 transition-all duration-300 shadow-lg mx-auto mb-4">
                  <Brain className="w-9 h-9 text-white" />
                </div>
                <h3 className="text-white font-semibold text-lg mb-2">
                  AI-Powered Analysis
                </h3>
              </motion.div>

              <motion.div
                className="group cursor-pointer text-center"
                whileHover={{ scale: 1.05 }}
                transition={{ duration: 0.2 }}
              >
                <div className="w-20 h-20 rounded-2xl bg-white/8 backdrop-blur-xl border border-white/30 flex items-center justify-center hover:bg-white/15 hover:border-white/50 transition-all duration-300 shadow-lg mx-auto mb-4">
                  <Lock className="w-9 h-9 text-white" />
                </div>
                <h3 className="text-white font-semibold text-lg mb-2">
                  Secure Infrastructure
                </h3>
              </motion.div>

              <motion.div
                className="group cursor-pointer text-center"
                whileHover={{ scale: 1.05 }}
                transition={{ duration: 0.2 }}
              >
                <div className="w-20 h-20 rounded-2xl bg-white/8 backdrop-blur-xl border border-white/30 flex items-center justify-center hover:bg-white/15 hover:border-white/50 transition-all duration-300 shadow-lg mx-auto mb-4">
                  <Eye className="w-9 h-9 text-white" />
                </div>
                <h3 className="text-white font-semibold text-lg mb-2">
                  Real-time Monitoring
                </h3>
              </motion.div>

              <motion.div
                className="group cursor-pointer text-center"
                whileHover={{ scale: 1.05 }}
                transition={{ duration: 0.2 }}
              >
                <div className="w-20 h-20 rounded-2xl bg-white/8 backdrop-blur-xl border border-white/30 flex items-center justify-center hover:bg-white/15 hover:border-white/50 transition-all duration-300 shadow-lg mx-auto mb-4">
                  <Zap className="w-9 h-9 text-white" />
                </div>
                <h3 className="text-white font-semibold text-lg mb-2">
                  Lightning Fast
                </h3>
              </motion.div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
