import { useRef, useState } from "react";
import { Link } from "wouter";
import {
  useListFirmware,
  getListFirmwareQueryKey,
  useDeleteFirmware,
  useStartScan
} from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  HardDrive,
  Upload,
  Trash2,
  Search,
  Cpu,
  File,
  Hash,
  AlertCircle,
  ShieldAlert,
  Bug,
  Fingerprint,
  FileText,
  ChevronDown,
  Eye,
  Loader2
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useQueryClient } from "@tanstack/react-query";

export default function FirmwareLibrary() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: firmwares, isLoading } = useListFirmware({
    query: { queryKey: getListFirmwareQueryKey() }
  });

  const deleteMutation = useDeleteFirmware();
  const startScanMutation = useStartScan();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const uploadFile = async (file: File) => {
    // Frontend safety check: 2 GB
    const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;

    if (file.size > MAX_FILE_SIZE) {
      toast({
        title: "File Too Large",
        description: `${file.name} exceeds the maximum upload size of 2GB.`,
        variant: "destructive",
      });
      return;
    }

    setIsUploading(true);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("/api/firmware/upload", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({
          error: "Upload failed"
        }));

        throw new Error(err.error || "Upload failed");
      }

      toast({
        title: "Firmware Uploaded",
        description: `${file.name} ready for analysis.`,
      });

      queryClient.invalidateQueries({
        queryKey: getListFirmwareQueryKey()
      });
    } catch (err) {
      toast({
        title: "Upload Failed",
        description:
          err instanceof Error
            ? err.message
            : "Could not upload firmware",
        variant: "destructive",
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleUpload = (e: React.FormEvent) => {
    e.preventDefault();
    fileInputRef.current?.click();
  };

  const handleFileSelect = (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];

    if (file) {
      void uploadFile(file);
    }

    e.target.value = "";
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const file = e.dataTransfer.files?.[0];

    if (file) {
      void uploadFile(file);
    }
  };

  const handleDelete = (id: number) => {
    deleteMutation.mutate(
      { id },
      {
        onSuccess: () => {
          toast({
            title: "Firmware Deleted",
            description: "Successfully removed from library.",
          });

          queryClient.invalidateQueries({
            queryKey: getListFirmwareQueryKey()
          });

          setExpandedId(null);
        }
      }
    );
  };

  const handleStartScan = (id: number) => {
    startScanMutation.mutate(
      { data: { firmwareId: id } },
      {
        onSuccess: () => {
          toast({
            title: "Scan Initiated",
            description: "Firmware analysis in progress.",
          });

          queryClient.invalidateQueries({
            queryKey: getListFirmwareQueryKey()
          });
        }
      }
    );
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "completed":
        return (
          <Badge
            variant="outline"
            className="bg-green-500/10 text-green-500 border-green-500/30"
          >
            COMPLETED
          </Badge>
        );

      case "scanning":
        return (
          <Badge
            variant="outline"
            className="bg-blue-500/10 text-blue-400 border-blue-500/30 animate-pulse"
          >
            SCANNING
          </Badge>
        );

      case "failed":
        return (
          <Badge
            variant="outline"
            className="bg-destructive/10 text-destructive border-destructive/30"
          >
            FAILED
          </Badge>
        );

      default:
        return (
          <Badge
            variant="outline"
            className="bg-muted text-muted-foreground border-border"
          >
            PENDING
          </Badge>
        );
    }
  };

  const analysisLinks = (fwId: number) => [
    {
      href: `/scan/${fwId}`,
      label: "Scan Details",
      icon: Eye,
      color: "text-primary"
    },
    {
      href: `/security/${fwId}`,
      label: "Security Analysis",
      icon: ShieldAlert,
      color: "text-orange-500"
    },
    {
      href: `/cve/${fwId}`,
      label: "CVE Intelligence",
      icon: Bug,
      color: "text-red-500"
    },
    {
      href: `/malware/${fwId}`,
      label: "Malware Detection",
      icon: Fingerprint,
      color: "text-purple-500"
    },
    {
      href: `/reports/${fwId}`,
      label: "Reports & AI",
      icon: FileText,
      color: "text-primary"
    },
  ];

  return (
    <div className="space-y-6">
      <motion.h1
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-3xl font-bold font-mono text-primary flex items-center drop-shadow-[0_0_8px_rgba(0,255,255,0.5)]"
      >
        <HardDrive className="mr-3 text-primary" />
        FIRMWARE_LIBRARY
      </motion.h1>

      <div className="grid md:grid-cols-3 gap-6">

        {/* UPLOAD CARD */}
        <Card className="border-primary/30 bg-card/80 backdrop-blur-md shadow-[0_0_15px_rgba(0,255,255,0.05)] md:col-span-1">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2 flex items-center">
              <Upload className="w-4 h-4 mr-2" />
              Ingest Binary
            </CardTitle>
          </CardHeader>

          <CardContent>
            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-all duration-300 ${
                isDragging
                  ? "border-primary bg-primary/5"
                  : "border-border hover:border-primary/50 bg-background/50"
              }`}
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="*/*"
                className="hidden"
                onChange={handleFileSelect}
              />

              <File className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-50" />

              <p className="font-mono text-sm text-muted-foreground mb-2">
                Drag &amp; Drop Firmware Binary
              </p>

              <p className="text-xs text-muted-foreground/60 mb-6">
                Supports all firmware, disk images &amp; archives (Max 2GB)
              </p>

              <form onSubmit={handleUpload}>
                <Button
                  type="submit"
                  className="w-full font-mono uppercase text-xs"
                  variant="outline"
                  disabled={isUploading}
                  data-testid="btn-upload-firmware"
                >
                  {isUploading ? (
                    <>
                      <Loader2 className="w-3 h-3 mr-2 animate-spin" />
                      Uploading...
                    </>
                  ) : (
                    "Upload Firmware"
                  )}
                </Button>
              </form>
            </div>
          </CardContent>
        </Card>

        {/* FIRMWARE TABLE */}
        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg md:col-span-2">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">
              Indexed Images
            </CardTitle>
          </CardHeader>

          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-6 space-y-4">
                <Skeleton className="h-10 w-full bg-muted/20" />
                <Skeleton className="h-10 w-full bg-muted/20" />
                <Skeleton className="h-10 w-full bg-muted/20" />
              </div>
            ) : firmwares && firmwares.length > 0 ? (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader className="bg-muted/10">
                    <TableRow className="border-border/50">
                      <TableHead className="font-mono text-xs uppercase text-muted-foreground">
                        ID / Name
                      </TableHead>

                      <TableHead className="font-mono text-xs uppercase text-muted-foreground">
                        Arch
                      </TableHead>

                      <TableHead className="font-mono text-xs uppercase text-muted-foreground">
                        Vendor
                      </TableHead>

                      <TableHead className="font-mono text-xs uppercase text-muted-foreground">
                        Size
                      </TableHead>

                      <TableHead className="font-mono text-xs uppercase text-muted-foreground">
                        Status
                      </TableHead>

                      <TableHead className="font-mono text-xs uppercase text-muted-foreground text-right">
                        Actions
                      </TableHead>
                    </TableRow>
                  </TableHeader>

                  <TableBody>
                    {[...firmwares]
                      .sort((a, b) => b.id - a.id)
                      .map((fw) => (
                        <>
                          <TableRow
                            key={fw.id}
                            className="border-border/50 hover:bg-muted/10 transition-colors group"
                          >
                            <TableCell className="font-mono text-sm">
                              <div className="font-semibold text-foreground group-hover:text-primary transition-colors flex items-center">
                                <span className="text-muted-foreground mr-2 text-xs">
                                  #{fw.id}
                                </span>
                                {fw.name}
                              </div>

                              <div className="text-xs text-muted-foreground mt-1 flex items-center truncate max-w-[200px]">
                                <Hash className="w-3 h-3 mr-1 inline" />
                                {fw.hashValue.substring(0, 16)}...
                              </div>
                            </TableCell>

                            <TableCell className="font-mono text-xs">
                              <div className="flex items-center">
                                <Cpu className="w-3 h-3 mr-1 text-muted-foreground" />
                                {fw.architecture}
                              </div>
                            </TableCell>

                            <TableCell className="font-mono text-xs">
                              {fw.vendor || "Unknown"}
                            </TableCell>

                            <TableCell className="font-mono text-xs text-muted-foreground">
                              {(fw.fileSize / 1024 / 1024).toFixed(2)} MB
                            </TableCell>

                            <TableCell>
                              {getStatusBadge(fw.status)}
                            </TableCell>

                            <TableCell className="text-right">
                              <div className="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                {fw.status === "pending" ||
                                fw.status === "failed" ? (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className="h-8 px-2 font-mono text-xs bg-primary/10 text-primary hover:bg-primary hover:text-primary-foreground border-primary/30"
                                    onClick={() =>
                                      handleStartScan(fw.id)
                                    }
                                    disabled={startScanMutation.isPending}
                                    data-testid={`btn-scan-${fw.id}`}
                                  >
                                    <Search className="w-3 h-3 mr-1" />
                                    Scan
                                  </Button>
                                ) : fw.status === "scanning" ? (
                                  <Link href={`/scan/${fw.id}`}>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="h-8 px-2 font-mono text-xs bg-blue-500/10 text-blue-400 border-blue-500/30"
                                      data-testid={`btn-progress-${fw.id}`}
                                    >
                                      <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                                      Progress
                                    </Button>
                                  </Link>
                                ) : (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className={`h-8 px-2 font-mono text-xs transition-all ${
                                      expandedId === fw.id
                                        ? "bg-primary/20 text-primary border-primary/50"
                                        : ""
                                    }`}
                                    onClick={() =>
                                      setExpandedId(
                                        expandedId === fw.id
                                          ? null
                                          : fw.id
                                      )
                                    }
                                    data-testid={`btn-view-${fw.id}`}
                                  >
                                    <ChevronDown
                                      className={`w-3 h-3 mr-1 transition-transform ${
                                        expandedId === fw.id
                                          ? "rotate-180"
                                          : ""
                                      }`}
                                    />
                                    Analyse
                                  </Button>
                                )}

                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-8 w-8 p-0 text-destructive hover:bg-destructive/20 hover:text-destructive"
                                  onClick={() =>
                                    handleDelete(fw.id)
                                  }
                                  disabled={deleteMutation.isPending}
                                  data-testid={`btn-delete-${fw.id}`}
                                >
                                  <Trash2 className="w-4 h-4" />
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>

                          {expandedId === fw.id && (
                            <TableRow
                              key={`${fw.id}-expand`}
                              className="border-border/20 bg-muted/5"
                            >
                              <TableCell
                                colSpan={5}
                                className="py-3 px-4"
                              >
                                <AnimatePresence>
                                  <motion.div
                                    initial={{
                                      opacity: 0,
                                      height: 0
                                    }}
                                    animate={{
                                      opacity: 1,
                                      height: "auto"
                                    }}
                                    exit={{
                                      opacity: 0,
                                      height: 0
                                    }}
                                    className="grid grid-cols-3 md:grid-cols-5 gap-2"
                                  >
                                    {analysisLinks(fw.id).map(
                                      ({
                                        href,
                                        label,
                                        icon: Icon,
                                        color
                                      }) => (
                                        <Link
                                          key={href}
                                          href={href}
                                        >
                                          <div
                                            className={`flex flex-col items-center gap-1.5 p-2.5 rounded-md border border-border/30 cursor-pointer hover:bg-muted/30 transition-all duration-200 ${color}`}
                                          >
                                            <Icon className="w-4 h-4" />
                                            <span className="font-mono text-[9px] uppercase text-center leading-tight text-muted-foreground">
                                              {label}
                                            </span>
                                          </div>
                                        </Link>
                                      )
                                    )}
                                  </motion.div>
                                </AnimatePresence>
                              </TableCell>
                            </TableRow>
                          )}
                        </>
                      ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="p-12 text-center flex flex-col items-center">
                <AlertCircle className="w-12 h-12 text-muted-foreground/30 mb-4" />

                <h3 className="font-mono text-lg text-muted-foreground mb-1">
                  DATASTORE_EMPTY
                </h3>

                <p className="text-sm text-muted-foreground/60">
                  Upload a firmware image to begin analysis.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}