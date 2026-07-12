package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OpenAIRequest defines standard OpenAI chat completions request schema
type OpenAIRequest struct {
	Model       string          `json:"model"`
	Messages    []OpenAIMessage `json:"messages"`
	Temperature float64         `json:"temperature,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
}

// OpenAIMessage schema
type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIResponse schema
type OpenAIResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []OpenAIChoice `json:"choices"`
	Usage   OpenAIUsage    `json:"usage"`
}

type OpenAIChoice struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type OpenAIUsage struct {
	PromptTokens            int                      `json:"prompt_tokens"`
	CompletionTokens        int                      `json:"completion_tokens"`
	TotalTokens             int                      `json:"total_tokens"`
	PromptTokensDetails     *OpenAIPromptDetails     `json:"prompt_tokens_details,omitempty"`
	CompletionTokensDetails *OpenAICompletionDetails `json:"completion_tokens_details,omitempty"`
}

type OpenAIPromptDetails struct {
	CachedTokens int `json:"cached_tokens"`
}

type OpenAICompletionDetails struct {
	ReasoningTokens int `json:"reasoning_tokens"`
}

// GeminiRequest structure
type GeminiRequest struct {
	Contents          []GeminiContent    `json:"contents"`
	SystemInstruction *GeminiInstruction `json:"systemInstruction,omitempty"`
	GenerationConfig  *GeminiConfig      `json:"generationConfig,omitempty"`
}

type GeminiContent struct {
	Role  string       `json:"role"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiInstruction struct {
	Parts []GeminiPart `json:"parts"`
}

type GeminiConfig struct {
	Temperature float64 `json:"temperature,omitempty"`
	MaxOutputTokens   int `json:"maxOutputTokens,omitempty"`
}

// GeminiResponse structure
type GeminiResponse struct {
	Candidates []GeminiCandidate `json:"candidates"`
}

type GeminiCandidate struct {
	Content struct {
		Parts []GeminiPart `json:"parts"`
		Role  string       `json:"role"`
	} `json:"content"`
	FinishReason string `json:"finishReason"`
}

// ClaudeRequest structure
type ClaudeRequest struct {
	Model     string          `json:"model"`
	Messages  []ClaudeMessage `json:"messages"`
	System    string          `json:"system,omitempty"`
	MaxTokens int             `json:"max_tokens"`
}

type ClaudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ClaudeResponse structure
type ClaudeResponse struct {
	ID      string `json:"id"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
	} `json:"usage"`
}

// TranslateRequest converts standard OpenAI format into target model provider format
func TranslateRequest(provider, targetModel string, openAIBytes []byte) ([]byte, error) {
	var req OpenAIRequest
	if err := json.Unmarshal(openAIBytes, &req); err != nil {
		return nil, err
	}

	// Override model if config specifies targetModel
	modelName := req.Model
	if targetModel != "" {
		modelName = targetModel
	}

	switch provider {
	case "gemini":
		var geminiReq GeminiRequest
		var systemPrompt string

		for _, msg := range req.Messages {
			if msg.Role == "system" {
				systemPrompt += msg.Content + "\n"
			} else {
				role := "user"
				if msg.Role == "assistant" {
					role = "model"
				}
				geminiReq.Contents = append(geminiReq.Contents, GeminiContent{
					Role:  role,
					Parts: []GeminiPart{{Text: msg.Content}},
				})
			}
		}

		if systemPrompt != "" {
			geminiReq.SystemInstruction = &GeminiInstruction{
				Parts: []GeminiPart{{Text: strings.TrimSpace(systemPrompt)}},
			}
		}

		if req.Temperature > 0 || req.MaxTokens > 0 {
			geminiReq.GenerationConfig = &GeminiConfig{
				Temperature:     req.Temperature,
				MaxOutputTokens: req.MaxTokens,
			}
		}

		return json.Marshal(geminiReq)

	case "anthropic":
		var claudeReq ClaudeRequest
		claudeReq.Model = modelName
		claudeReq.MaxTokens = req.MaxTokens
		if claudeReq.MaxTokens == 0 {
			claudeReq.MaxTokens = 1024 // Anthropic requires max_tokens
		}

		var systemPrompt string
		for _, msg := range req.Messages {
			if msg.Role == "system" {
				systemPrompt += msg.Content + "\n"
			} else {
				role := "user"
				if msg.Role == "assistant" {
					role = "assistant"
				}
				claudeReq.Messages = append(claudeReq.Messages, ClaudeMessage{
					Role:    role,
					Content: msg.Content,
				})
			}
		}

		if systemPrompt != "" {
			claudeReq.System = strings.TrimSpace(systemPrompt)
		}

		return json.Marshal(claudeReq)

	default: // openai, grok, ollama, lmstudio, mock
		// Update model name if overridden
		if targetModel != "" {
			req.Model = targetModel
		}
		return json.Marshal(req)
	}
}

// TranslateResponse converts native response formats back to standard OpenAI completions format
func TranslateResponse(provider, targetModel string, nativeBytes []byte) ([]byte, error) {
	switch provider {
	case "gemini":
		var gemResp GeminiResponse
		if err := json.Unmarshal(nativeBytes, &gemResp); err != nil {
			return nil, err
		}

		if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
			return nil, fmt.Errorf("empty gemini response candidates")
		}

		responseText := gemResp.Candidates[0].Content.Parts[0].Text

		openAIResp := OpenAIResponse{
			ID:      fmt.Sprintf("gemini-chatcmpl-%d", time.Now().UnixNano()),
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   targetModel,
			Choices: []OpenAIChoice{
				{
					Index: 0,
					Message: OpenAIMessage{
						Role:    "assistant",
						Content: responseText,
					},
					FinishReason: gemResp.Candidates[0].FinishReason,
				},
			},
			Usage: OpenAIUsage{
				PromptTokens:     0,
				CompletionTokens: 0,
				TotalTokens:      0,
			},
		}
		return json.Marshal(openAIResp)

	case "anthropic":
		var claudeResp ClaudeResponse
		if err := json.Unmarshal(nativeBytes, &claudeResp); err != nil {
			return nil, err
		}

		responseText := ""
		if len(claudeResp.Content) > 0 {
			responseText = claudeResp.Content[0].Text
		}

		var promptDetails *OpenAIPromptDetails
		if claudeResp.Usage.CacheReadInputTokens > 0 {
			promptDetails = &OpenAIPromptDetails{
				CachedTokens: claudeResp.Usage.CacheReadInputTokens,
			}
		}

		openAIResp := OpenAIResponse{
			ID:      claudeResp.ID,
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   claudeResp.Model,
			Choices: []OpenAIChoice{
				{
					Index: 0,
					Message: OpenAIMessage{
						Role:    "assistant",
						Content: responseText,
					},
					FinishReason: claudeResp.StopReason,
				},
			},
			Usage: OpenAIUsage{
				PromptTokens:        claudeResp.Usage.InputTokens,
				CompletionTokens:    claudeResp.Usage.OutputTokens,
				TotalTokens:         claudeResp.Usage.InputTokens + claudeResp.Usage.OutputTokens,
				PromptTokensDetails: promptDetails,
			},
		}
		return json.Marshal(openAIResp)

	default: // openai, grok, ollama, lmstudio, mock
		// Already in OpenAI format, return as is
		return nativeBytes, nil
	}
}
