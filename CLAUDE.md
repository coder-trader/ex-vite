# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a minimal Vite + TypeScript project that creates a simple counter application. The project follows Vite's standard structure with TypeScript configuration optimized for modern development.

## Development Commands

- `pnpm dev` - Start development server
- `pnpm build` - Build for production (runs TypeScript compiler then Vite build)
- `pnpm preview` - Preview production build locally

## Architecture

The project uses a simple modular structure:

- `src/main.ts` - Entry point that sets up the DOM and initializes the counter
- `src/counter.ts` - Counter functionality as a reusable module
- `src/style.css` - Application styles
- `index.html` - HTML template with Vite integration

## TypeScript Configuration

The project uses strict TypeScript settings with:
- Target: ES2022
- Module resolution: bundler mode
- Strict linting enabled (unused locals, parameters, etc.)
- No emit mode (Vite handles compilation)

## Build System

Uses Vite as the build tool with TypeScript compilation. The build process:
1. TypeScript compiler checks types
2. Vite bundles and optimizes for production

Static assets are served from the `public/` directory and source files from `src/`.