/**
 * VoiceFlow VS Code Extension
 * 
 * Advanced voice-to-text integration with syntax-aware text injection,
 * programming language support, and intelligent code generation.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import axios from 'axios';
import WebSocket from 'ws';

interface VoiceFlowConfig {
    serverUrl: string;
    smartMode: boolean;
    autoFormat: boolean;
    showStatusBar: boolean;
    aiEnhancement: boolean;
    languageSpecificPrompts: boolean;
    preserveSyntaxHighlighting: boolean;
    debugMode: boolean;
}

interface CodeContext {
    language: string;
    filePath?: string;
    cursorPosition: vscode.Position;
    selection?: vscode.Range;
    surroundingCode: {
        before: string;
        after: string;
    };
    indentationLevel: number;
    contextType: 'code' | 'comment' | 'string' | 'function' | 'variable' | 'class';
}

class VoiceFlowExtension {
    private statusBarItem: vscode.StatusBarItem;
    private webSocket: WebSocket | null = null;
    private isListening: boolean = false;
    private config: VoiceFlowConfig;
    private outputChannel: vscode.OutputChannel;
    private contextAnalyzer: CodeContextAnalyzer;

    constructor(private context: vscode.ExtensionContext) {
        this.config = this.loadConfiguration();
        this.outputChannel = vscode.window.createOutputChannel('VoiceFlow');
        this.contextAnalyzer = new CodeContextAnalyzer();
        this.setupStatusBar();
        this.setupWebSocket();
        this.registerCommands();
        this.registerEventHandlers();
    }

    private loadConfiguration(): VoiceFlowConfig {
        const config = vscode.workspace.getConfiguration('voiceflow');
        return {
            serverUrl: config.get<string>('serverUrl', 'http://localhost:8000'),
            smartMode: config.get<boolean>('smartMode', true),
            autoFormat: config.get<boolean>('autoFormat', true),
            showStatusBar: config.get<boolean>('showStatusBar', true),
            aiEnhancement: config.get<boolean>('aiEnhancement', true),
            languageSpecificPrompts: config.get<boolean>('languageSpecificPrompts', true),
            preserveSyntaxHighlighting: config.get<boolean>('preserveSyntaxHighlighting', true),
            debugMode: config.get<boolean>('debugMode', false)
        };
    }

    private setupStatusBar(): void {
        if (!this.config.showStatusBar) {
            return;
        }

        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );
        
        this.statusBarItem.text = '$(mic) VoiceFlow';
        this.statusBarItem.tooltip = 'VoiceFlow: Click to start voice input';
        this.statusBarItem.command = 'voiceflow.startListening';
        this.statusBarItem.show();

        this.context.subscriptions.push(this.statusBarItem);
    }

    private async setupWebSocket(): Promise<void> {
        try {
            const wsUrl = this.config.serverUrl.replace(/^http/, 'ws') + '/ws';
            this.webSocket = new WebSocket(wsUrl);

            this.webSocket.on('open', () => {
                this.log('WebSocket connection established');
                this.updateStatusBar('Connected', '$(check)');
            });

            this.webSocket.on('message', (data: string) => {
                try {
                    const message = JSON.parse(data);
                    this.handleWebSocketMessage(message);
                } catch (error) {
                    this.log(`Error parsing WebSocket message: ${error}`);
                }
            });

            this.webSocket.on('close', () => {
                this.log('WebSocket connection closed');
                this.updateStatusBar('Disconnected', '$(x)');
                this.webSocket = null;
                
                // Attempt to reconnect after 5 seconds
                setTimeout(() => this.setupWebSocket(), 5000);
            });

            this.webSocket.on('error', (error) => {
                this.log(`WebSocket error: ${error}`);
                this.updateStatusBar('Error', '$(warning)');
            });

        } catch (error) {
            this.log(`Failed to setup WebSocket: ${error}`);
            this.updateStatusBar('Failed to connect', '$(warning)');
        }
    }

    private handleWebSocketMessage(message: any): void {
        switch (message.type) {
            case 'transcription':
                this.handleTranscription(message.data);
                break;
            case 'status':
                this.handleStatusUpdate(message.data);
                break;
            case 'error':
                this.handleError(message.data);
                break;
            default:
                this.log(`Unknown message type: ${message.type}`);
        }
    }

    private async handleTranscription(data: any): Promise<void> {
        const { text, confidence, language } = data;
        
        if (!text || confidence < 0.5) {
            this.log(`Low confidence transcription ignored: ${text} (${confidence})`);
            return;
        }

        this.log(`Transcription received: "${text}" (confidence: ${confidence})`);

        if (this.config.smartMode) {
            await this.injectTextWithContext(text, language);
        } else {
            await this.injectTextDirect(text);
        }
    }

    private handleStatusUpdate(data: any): void {
        const { listening, processing } = data;
        
        if (listening !== this.isListening) {
            this.isListening = listening;
            this.updateStatusBar(
                listening ? 'Listening...' : 'Ready',
                listening ? '$(record)' : '$(mic)'
            );
        }

        if (processing) {
            this.updateStatusBar('Processing...', '$(loading~spin)');
        }
    }

    private handleError(data: any): void {
        const { message, code } = data;
        this.log(`Error: ${message} (${code})`);
        vscode.window.showErrorMessage(`VoiceFlow Error: ${message}`);
    }

    private async injectTextWithContext(text: string, detectedLanguage?: string): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found');
            return;
        }

        try {
            // Analyze current code context
            const context = await this.contextAnalyzer.analyzeContext(editor, detectedLanguage);
            
            // Get enhanced text from server
            const enhancedText = await this.enhanceTextWithContext(text, context);
            
            // Apply formatting based on context
            const formattedText = this.formatTextForContext(enhancedText, context);
            
            // Insert text with syntax highlighting preservation
            await this.insertTextPreservingSyntax(editor, formattedText, context);
            
            this.log(`Text injected with context: "${formattedText}"`);

        } catch (error) {
            this.log(`Error injecting text with context: ${error}`);
            // Fallback to direct injection
            await this.injectTextDirect(text);
        }
    }

    private async enhanceTextWithContext(text: string, context: CodeContext): Promise<string> {
        if (!this.config.aiEnhancement) {
            return text;
        }

        try {
            const response = await axios.post(`${this.config.serverUrl}/api/enhance`, {
                text,
                context: {
                    language: context.language,
                    contextType: context.contextType,
                    filePath: context.filePath,
                    cursorPosition: context.cursorPosition,
                    indentationLevel: context.indentationLevel,
                    surroundingCode: context.surroundingCode
                },
                options: {
                    languageSpecific: this.config.languageSpecificPrompts,
                    autoFormat: this.config.autoFormat
                }
            });

            return response.data.enhancedText || text;

        } catch (error) {
            this.log(`Enhancement request failed: ${error}`);
            return text;
        }
    }

    private formatTextForContext(text: string, context: CodeContext): string {
        if (!this.config.autoFormat) {
            return text;
        }

        // Apply language-specific formatting
        switch (context.language) {
            case 'python':
                return this.formatPythonText(text, context);
            case 'javascript':
            case 'typescript':
                return this.formatJavaScriptText(text, context);
            case 'java':
                return this.formatJavaText(text, context);
            case 'cpp':
            case 'c':
                return this.formatCppText(text, context);
            default:
                return this.formatGenericText(text, context);
        }
    }

    private formatPythonText(text: string, context: CodeContext): string {
        const indent = '    '.repeat(context.indentationLevel);
        
        switch (context.contextType) {
            case 'comment':
                return `${indent}# ${text}`;
            case 'function':
                const funcName = this.toSnakeCase(text);
                return `${indent}def ${funcName}():`;
            case 'variable':
                const varName = this.toSnakeCase(text);
                return `${indent}${varName} = `;
            case 'class':
                const className = this.toPascalCase(text);
                return `${indent}class ${className}:`;
            default:
                return `${indent}${text}`;
        }
    }

    private formatJavaScriptText(text: string, context: CodeContext): string {
        const indent = '  '.repeat(context.indentationLevel);
        
        switch (context.contextType) {
            case 'comment':
                return `${indent}// ${text}`;
            case 'function':
                const funcName = this.toCamelCase(text);
                return `${indent}function ${funcName}() {`;
            case 'variable':
                const varName = this.toCamelCase(text);
                return `${indent}const ${varName} = `;
            case 'class':
                const className = this.toPascalCase(text);
                return `${indent}class ${className} {`;
            default:
                return `${indent}${text}`;
        }
    }

    private formatJavaText(text: string, context: CodeContext): string {
        const indent = '    '.repeat(context.indentationLevel);
        
        switch (context.contextType) {
            case 'comment':
                return `${indent}// ${text}`;
            case 'function':
                const methodName = this.toCamelCase(text);
                return `${indent}public void ${methodName}() {`;
            case 'variable':
                const varName = this.toCamelCase(text);
                return `${indent}String ${varName} = `;
            case 'class':
                const className = this.toPascalCase(text);
                return `${indent}public class ${className} {`;
            default:
                return `${indent}${text}`;
        }
    }

    private formatCppText(text: string, context: CodeContext): string {
        const indent = '    '.repeat(context.indentationLevel);
        
        switch (context.contextType) {
            case 'comment':
                return `${indent}// ${text}`;
            case 'function':
                const funcName = this.toSnakeCase(text);
                return `${indent}void ${funcName}() {`;
            case 'variable':
                const varName = this.toSnakeCase(text);
                return `${indent}auto ${varName} = `;
            default:
                return `${indent}${text}`;
        }
    }

    private formatGenericText(text: string, context: CodeContext): string {
        const indent = '    '.repeat(context.indentationLevel);
        return `${indent}${text}`;
    }

    private async insertTextPreservingSyntax(
        editor: vscode.TextEditor, 
        text: string, 
        context: CodeContext
    ): Promise<void> {
        if (!this.config.preserveSyntaxHighlighting) {
            return this.injectTextDirect(text);
        }

        await editor.edit(editBuilder => {
            // If there's a selection, replace it
            if (context.selection && !context.selection.isEmpty) {
                editBuilder.replace(context.selection, text);
            } else {
                // Insert at cursor position
                editBuilder.insert(context.cursorPosition, text);
            }
        });

        // Trigger syntax highlighting update
        await vscode.commands.executeCommand('editor.action.formatDocument');
    }

    private async injectTextDirect(text: string): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return;
        }

        await editor.edit(editBuilder => {
            const position = editor.selection.active;
            editBuilder.insert(position, text);
        });
    }

    private registerCommands(): void {
        // Start listening command
        const startListening = vscode.commands.registerCommand('voiceflow.startListening', () => {
            this.startListening();
        });

        // Stop listening command
        const stopListening = vscode.commands.registerCommand('voiceflow.stopListening', () => {
            this.stopListening();
        });

        // Inject text command
        const injectText = vscode.commands.registerCommand('voiceflow.injectText', async () => {
            const text = await vscode.window.showInputBox({
                prompt: 'Enter text to inject',
                placeHolder: 'Text to inject at cursor position'
            });

            if (text) {
                if (this.config.smartMode) {
                    await this.injectTextWithContext(text);
                } else {
                    await this.injectTextDirect(text);
                }
            }
        });

        // Toggle smart mode command
        const toggleSmartMode = vscode.commands.registerCommand('voiceflow.toggleSmartMode', () => {
            this.config.smartMode = !this.config.smartMode;
            const config = vscode.workspace.getConfiguration('voiceflow');
            config.update('smartMode', this.config.smartMode);
            
            vscode.window.showInformationMessage(
                `VoiceFlow Smart Mode: ${this.config.smartMode ? 'Enabled' : 'Disabled'}`
            );
        });

        // Show status command
        const showStatus = vscode.commands.registerCommand('voiceflow.showStatus', () => {
            this.showStatusPanel();
        });

        // Open settings command
        const openSettings = vscode.commands.registerCommand('voiceflow.openSettings', () => {
            vscode.commands.executeCommand('workbench.action.openSettings', 'voiceflow');
        });

        this.context.subscriptions.push(
            startListening,
            stopListening,
            injectText,
            toggleSmartMode,
            showStatus,
            openSettings
        );
    }

    private registerEventHandlers(): void {
        // Configuration change handler
        const configChangeHandler = vscode.workspace.onDidChangeConfiguration(event => {
            if (event.affectsConfiguration('voiceflow')) {
                this.config = this.loadConfiguration();
                this.log('Configuration updated');
            }
        });

        // Active editor change handler
        const editorChangeHandler = vscode.window.onDidChangeActiveTextEditor(() => {
            // Update context when switching editors
            if (this.config.smartMode) {
                this.updateContextInfo();
            }
        });

        this.context.subscriptions.push(configChangeHandler, editorChangeHandler);
    }

    private async startListening(): Promise<void> {
        if (!this.webSocket || this.webSocket.readyState !== WebSocket.OPEN) {
            vscode.window.showErrorMessage('VoiceFlow server not connected');
            return;
        }

        try {
            this.webSocket.send(JSON.stringify({
                type: 'start_listening',
                data: {
                    smartMode: this.config.smartMode,
                    context: this.config.smartMode ? await this.getCurrentContext() : null
                }
            }));

            this.isListening = true;
            this.updateStatusBar('Listening...', '$(record)');
            vscode.commands.executeCommand('setContext', 'voiceflow.listening', true);

        } catch (error) {
            this.log(`Error starting listening: ${error}`);
            vscode.window.showErrorMessage('Failed to start voice input');
        }
    }

    private async stopListening(): Promise<void> {
        if (!this.webSocket || !this.isListening) {
            return;
        }

        try {
            this.webSocket.send(JSON.stringify({
                type: 'stop_listening'
            }));

            this.isListening = false;
            this.updateStatusBar('Ready', '$(mic)');
            vscode.commands.executeCommand('setContext', 'voiceflow.listening', false);

        } catch (error) {
            this.log(`Error stopping listening: ${error}`);
        }
    }

    private async getCurrentContext(): Promise<any> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return null;
        }

        return {
            language: editor.document.languageId,
            filePath: editor.document.fileName,
            cursorPosition: editor.selection.active,
            workspaceFolder: vscode.workspace.getWorkspaceFolder(editor.document.uri)?.uri.fsPath
        };
    }

    private updateContextInfo(): void {
        // This could be extended to show context information in the status bar
        // or a dedicated view
    }

    private showStatusPanel(): void {
        const panel = vscode.window.createWebviewPanel(
            'voiceflowStatus',
            'VoiceFlow Status',
            vscode.ViewColumn.Beside,
            {
                enableScripts: true
            }
        );

        panel.webview.html = this.getStatusPanelHtml();
    }

    private getStatusPanelHtml(): string {
        const connectionStatus = this.webSocket?.readyState === WebSocket.OPEN ? 'Connected' : 'Disconnected';
        const listeningStatus = this.isListening ? 'Listening' : 'Idle';

        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>VoiceFlow Status</title>
                <style>
                    body { font-family: var(--vscode-font-family); padding: 20px; }
                    .status-item { margin: 10px 0; }
                    .status-label { font-weight: bold; }
                    .connected { color: var(--vscode-terminal-ansiGreen); }
                    .disconnected { color: var(--vscode-terminal-ansiRed); }
                    .listening { color: var(--vscode-terminal-ansiYellow); }
                </style>
            </head>
            <body>
                <h1>VoiceFlow Status</h1>
                
                <div class="status-item">
                    <span class="status-label">Connection:</span>
                    <span class="${connectionStatus.toLowerCase()}">${connectionStatus}</span>
                </div>
                
                <div class="status-item">
                    <span class="status-label">Listening:</span>
                    <span class="${this.isListening ? 'listening' : ''}">${listeningStatus}</span>
                </div>
                
                <div class="status-item">
                    <span class="status-label">Smart Mode:</span>
                    <span>${this.config.smartMode ? 'Enabled' : 'Disabled'}</span>
                </div>
                
                <div class="status-item">
                    <span class="status-label">AI Enhancement:</span>
                    <span>${this.config.aiEnhancement ? 'Enabled' : 'Disabled'}</span>
                </div>
                
                <div class="status-item">
                    <span class="status-label">Server URL:</span>
                    <span>${this.config.serverUrl}</span>
                </div>
            </body>
            </html>
        `;
    }

    private updateStatusBar(text: string, icon: string): void {
        if (this.statusBarItem) {
            this.statusBarItem.text = `${icon} ${text}`;
        }
    }

    private log(message: string): void {
        if (this.config.debugMode) {
            this.outputChannel.appendLine(`[${new Date().toISOString()}] ${message}`);
        }
    }

    // Utility methods for naming conventions
    private toCamelCase(text: string): string {
        const words = text.toLowerCase().split(/\s+/);
        return words[0] + words.slice(1).map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join('');
    }

    private toPascalCase(text: string): string {
        const words = text.toLowerCase().split(/\s+/);
        return words.map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join('');
    }

    private toSnakeCase(text: string): string {
        return text.toLowerCase().replace(/\s+/g, '_');
    }

    dispose(): void {
        if (this.webSocket) {
            this.webSocket.close();
        }
        
        if (this.statusBarItem) {
            this.statusBarItem.dispose();
        }
        
        this.outputChannel.dispose();
    }
}

class CodeContextAnalyzer {
    async analyzeContext(editor: vscode.TextEditor, detectedLanguage?: string): Promise<CodeContext> {
        const document = editor.document;
        const position = editor.selection.active;
        const selection = editor.selection.isEmpty ? undefined : editor.selection;
        
        // Get surrounding code for context
        const lineText = document.lineAt(position.line).text;
        const beforeCursor = lineText.substring(0, position.character);
        const afterCursor = lineText.substring(position.character);
        
        // Analyze indentation
        const indentationLevel = this.getIndentationLevel(lineText);
        
        // Determine context type
        const contextType = this.determineContextType(document, position);
        
        // Get surrounding lines for better context
        const surroundingCode = this.getSurroundingCode(document, position);
        
        return {
            language: detectedLanguage || document.languageId,
            filePath: document.fileName,
            cursorPosition: position,
            selection,
            surroundingCode,
            indentationLevel,
            contextType
        };
    }

    private getIndentationLevel(line: string): number {
        const match = line.match(/^(\s*)/);
        if (!match) return 0;
        
        const whitespace = match[1];
        // Assume 4 spaces or 1 tab per level
        return whitespace.includes('\t') ? 
            whitespace.length : 
            Math.floor(whitespace.length / 4);
    }

    private determineContextType(document: vscode.TextDocument, position: vscode.Position): CodeContext['contextType'] {
        const line = document.lineAt(position.line).text;
        const beforeCursor = line.substring(0, position.character);
        
        // Simple heuristics for context detection
        if (line.trim().startsWith('//') || line.trim().startsWith('#') || line.trim().startsWith('<!--')) {
            return 'comment';
        }
        
        if (beforeCursor.includes('"') || beforeCursor.includes("'") || beforeCursor.includes('`')) {
            return 'string';
        }
        
        if (line.includes('def ') || line.includes('function ') || line.includes('func ')) {
            return 'function';
        }
        
        if (line.includes('class ')) {
            return 'class';
        }
        
        if (line.includes('=') && !line.includes('==') && !line.includes('!=')) {
            return 'variable';
        }
        
        return 'code';
    }

    private getSurroundingCode(document: vscode.TextDocument, position: vscode.Position): { before: string; after: string } {
        const startLine = Math.max(0, position.line - 2);
        const endLine = Math.min(document.lineCount - 1, position.line + 2);
        
        const beforeLines: string[] = [];
        const afterLines: string[] = [];
        
        for (let i = startLine; i < position.line; i++) {
            beforeLines.push(document.lineAt(i).text);
        }
        
        for (let i = position.line + 1; i <= endLine; i++) {
            afterLines.push(document.lineAt(i).text);
        }
        
        return {
            before: beforeLines.join('\n'),
            after: afterLines.join('\n')
        };
    }
}

export function activate(context: vscode.ExtensionContext) {
    const extension = new VoiceFlowExtension(context);
    
    // Set extension as enabled
    vscode.commands.executeCommand('setContext', 'voiceflow.enabled', true);
    
    // Add to subscriptions for proper cleanup
    context.subscriptions.push({
        dispose: () => extension.dispose()
    });
    
    console.log('VoiceFlow extension is now active');
}

export function deactivate() {
    vscode.commands.executeCommand('setContext', 'voiceflow.enabled', false);
    vscode.commands.executeCommand('setContext', 'voiceflow.listening', false);
    console.log('VoiceFlow extension is now inactive');
}