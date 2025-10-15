import { useState, useRef, useEffect } from 'react';
import { MessageSquare, Send, Sparkles, FileText, AlertTriangle, Copy, ThumbsUp, ThumbsDown, Wifi, WifiOff } from 'lucide-react';
import { GlassmorphicLayout } from '../components/GlassmorphicLayout';
import { GlassmorphicNav } from '../components/GlassmorphicNav';
import { GlassmorphicCard, GlassmorphicCardHeader, GlassmorphicCardContent } from '../components/GlassmorphicCard';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { mockChatHistory } from '../utils/mockData';
import { motion } from 'motion/react';
// MoRSE service removed - using fallback responses
import { toast } from 'sonner';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  references?: string[];
}

export function ChatbotPage() {
  const [messages, setMessages] = useState<Message[]>(mockChatHistory);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  // MoRSE connection removed - using static responses
  const scrollRef = useRef<HTMLDivElement>(null);

  // MoRSE connection logic removed

  const suggestedQuestions = [
    "What are the critical vulnerabilities in the last scan?",
    "Explain the exploit chain for CVE-2024-1234",
    "How can I remediate SQL injection vulnerabilities?",
    "Show me the attack path to the database",
    "What ports are exposed in scan-001?",
  ];

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage: Message = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: input,
      timestamp: new Date().toISOString(),
    };

    setMessages(prev => [...prev, userMessage]);
    const currentInput = input;
    setInput('');
    setIsTyping(true);

    try {
      // Generate a simple fallback response
      const assistantMessage: Message = {
        id: `msg-${Date.now()}-response`,
        role: 'assistant',
        content: `I understand you're asking about "${currentInput}". \n\n🤖 **AI Assistant Response**\n\nThis is a placeholder response for your cybersecurity query. In a production environment, this would be connected to:\n\n- Advanced AI models for threat analysis\n- Real-time vulnerability databases\n- Exploit intelligence feeds\n- Security knowledge bases\n\nYour query would be processed to provide:\n- Detailed vulnerability analysis\n- Remediation recommendations\n- Threat intelligence insights\n- Security best practices\n\nPlease integrate your preferred AI service or security intelligence platform.`,
        timestamp: new Date().toISOString(),
        references: ['AI Assistant - Demo Mode'],
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (error) {
      console.error('Error sending message:', error);
      
      const errorMessage: Message = {
        id: `msg-${Date.now()}-error`,
        role: 'assistant',
        content: `❌ **Error processing your request**\n\nI encountered an issue while processing your query: "${currentInput}"\n\nThis could be due to:\n- MoRSE backend connectivity issues\n- High server load\n- Query processing timeout\n\nPlease try again or contact support if the issue persists.`,
        timestamp: new Date().toISOString(),
      };

      setMessages(prev => [...prev, errorMessage]);
      toast.error('Failed to process your query');
    } finally {
      setIsTyping(false);
    }
  };

  const handleSuggestion = (question: string) => {
    setInput(question);
  };

  const handleCopy = (content: string) => {
    navigator.clipboard.writeText(content);
  };

  return (
    <GlassmorphicLayout>
      <GlassmorphicNav />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <motion.div 
          className="mb-8"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.6 }}
        >
          <h1 className="text-3xl mb-2 text-white">AI Security Assistant</h1>
          <p className="text-white/60">Ask questions about vulnerabilities, exploits, and security analysis</p>
        </motion.div>

        <div className="grid lg:grid-cols-4 gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-4">
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-base text-white">Suggested Questions</h2>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-2">
                {suggestedQuestions.map((question, idx) => (
                  <motion.button
                    key={idx}
                    onClick={() => handleSuggestion(question)}
                    className="w-full text-left p-3 text-sm bg-white/5 hover:bg-white/10 rounded-xl transition-colors border border-white/10 text-white/80"
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    {question}
                  </motion.button>
                ))}
              </GlassmorphicCardContent>
            </GlassmorphicCard>

            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-base text-white">Context Sources</h2>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-2 text-sm">
                <div className="flex items-center gap-2 text-white/80">
                  <FileText className="h-4 w-4 text-blue-400" />
                  <span>Scan Reports (3)</span>
                </div>
                <div className="flex items-center gap-2 text-white/80">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  <span>CVE Database</span>
                </div>
                <div className="flex items-center gap-2 text-white/80">
                  <Sparkles className="h-4 w-4 text-purple-400" />
                  <span>Threat Intelligence</span>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>

            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <div className="flex items-center justify-between">
                  <h2 className="text-base text-white">AI Status</h2>
                  <div className="flex items-center gap-2">
                    <WifiOff className="h-4 w-4 text-orange-400" />
                    <Badge className="bg-orange-500/20 text-orange-300 border-orange-500/30">
                      Demo Mode
                    </Badge>
                  </div>
                </div>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="text-sm space-y-2">
                <div className="flex justify-between text-white/80">
                  <span className="text-white/60">Model</span>
                  <span>Placeholder</span>
                </div>
                <div className="flex justify-between text-white/80">
                  <span className="text-white/60">Context Size</span>
                  <span>Limited</span>
                </div>
                <div className="flex justify-between text-white/80">
                  <span className="text-white/60">Knowledge Base</span>
                  <span>Static</span>
                </div>
                <div className="mt-2 p-2 bg-orange-500/10 rounded-lg border border-orange-500/20">
                  <p className="text-xs text-orange-300">
                    Connect your AI service for full functionality
                  </p>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </div>

          {/* Chat Area */}
          <div className="lg:col-span-3">
            <GlassmorphicCard className="h-[700px] flex flex-col">
              <GlassmorphicCardHeader>
                <div className="flex items-center gap-2">
                  <MessageSquare className="h-5 w-5 text-white" />
                  <h2 className="text-xl text-white">Security Analysis Chat</h2>
                  <Badge className="ml-auto bg-purple-500/20 text-purple-300 border-purple-500/30">
                    <Sparkles className="h-3 w-3 mr-1" />
                    AI-Powered
                  </Badge>
                </div>
              </GlassmorphicCardHeader>
              
              <GlassmorphicCardContent className="flex-1 flex flex-col p-0">
                {/* Messages */}
                <div className="flex-1 overflow-auto p-6" ref={scrollRef}>
                  <div className="space-y-6">
                    {messages.map((message) => (
                      <div
                        key={message.id}
                        className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                      >
                        <div className={`max-w-3xl ${message.role === 'user' ? 'bg-emerald-500/20 border-emerald-500/30' : 'bg-white/5 border-white/10'} rounded-2xl p-4 border backdrop-blur-sm`}>
                          <div className="flex items-start gap-3">
                            {message.role === 'assistant' && (
                              <Sparkles className="h-5 w-5 text-purple-400 flex-shrink-0 mt-1" />
                            )}
                            <div className="flex-1">
                              <div className="whitespace-pre-wrap text-white/90">{message.content}</div>
                              
                              {message.references && message.references.length > 0 && (
                                <div className="mt-3 pt-3 border-t border-white/10">
                                  <div className="text-sm text-white/60 mb-2">References:</div>
                                  <div className="space-y-1">
                                    {message.references.map((ref, idx) => (
                                      <div key={idx} className="flex items-center gap-2 text-sm text-white/80">
                                        <FileText className="h-3 w-3" />
                                        <span>{ref}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {message.role === 'assistant' && (
                                <div className="flex items-center gap-2 mt-3">
                                  <motion.button
                                    className="px-3 py-1.5 bg-white/5 hover:bg-white/10 rounded-lg text-xs text-white/80 transition-colors border border-white/10 flex items-center gap-1"
                                    onClick={() => handleCopy(message.content)}
                                    whileHover={{ scale: 1.05 }}
                                    whileTap={{ scale: 0.95 }}
                                  >
                                    <Copy className="h-3 w-3" />
                                    Copy
                                  </motion.button>
                                  <motion.button 
                                    className="px-3 py-1.5 bg-white/5 hover:bg-white/10 rounded-lg text-xs text-white/80 transition-colors border border-white/10"
                                    whileHover={{ scale: 1.05 }}
                                    whileTap={{ scale: 0.95 }}
                                  >
                                    <ThumbsUp className="h-3 w-3" />
                                  </motion.button>
                                  <motion.button 
                                    className="px-3 py-1.5 bg-white/5 hover:bg-white/10 rounded-lg text-xs text-white/80 transition-colors border border-white/10"
                                    whileHover={{ scale: 1.05 }}
                                    whileTap={{ scale: 0.95 }}
                                  >
                                    <ThumbsDown className="h-3 w-3" />
                                  </motion.button>
                                </div>
                              )}
                            </div>
                          </div>
                          <div className={`text-xs mt-2 ${message.role === 'user' ? 'text-emerald-300' : 'text-white/40'}`}>
                            {new Date(message.timestamp).toLocaleTimeString()}
                          </div>
                        </div>
                      </div>
                    ))}
                    
                    {isTyping && (
                      <div className="flex justify-start">
                        <div className="bg-white/5 border border-white/10 rounded-2xl p-4 backdrop-blur-sm">
                          <div className="flex items-center gap-2">
                            <Sparkles className="h-5 w-5 text-purple-400 animate-pulse" />
                            <span className="text-white/60">AI is typing...</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Input */}
                <div className="border-t border-white/10 p-4 bg-white/5 rounded-b-3xl backdrop-blur-sm">
                  <div className="flex gap-2">
                    <Input
                      placeholder="Ask about vulnerabilities, exploits, or security recommendations..."
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleSend()}
                      className="flex-1 bg-white/5 border-white/10 text-white placeholder:text-white/40"
                    />
                    <motion.button 
                      onClick={handleSend} 
                      disabled={!input.trim() || isTyping}
                      className="px-6 py-2 bg-emerald-500/20 backdrop-blur-xl rounded-full border border-emerald-500/30 text-white hover:bg-emerald-500/30 transition-all shadow-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <Send className="h-4 w-4" />
                    </motion.button>
                  </div>
                  <div className="text-xs text-white/40 mt-2">
                    Press Enter to send • Demo mode - integrate your AI service for full functionality
                  </div>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </div>
        </div>
      </div>
    </GlassmorphicLayout>
  );
}
